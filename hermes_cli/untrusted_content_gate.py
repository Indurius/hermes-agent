"""Central policy API for dangerous transitions from untrusted content.

This module is intentionally pure and call-site scoped.  It does not install a
transparent global hook; callers explicitly evaluate transitions from known
external/untrusted provenance into risky targets such as execution, writes,
Kanban durability, memory, or skill mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Mapping, Sequence

from hermes_cli.security_review_gate import (
    assert_durable_kanban_safe,
    sanitize_for_durable_kanban,
)

GateLevel = Literal["allow", "warn", "review", "block", "needs-human"]
ReviewResult = Literal["safe", "suspicious", "blocked", "needs-human", "reviewer_failed"]

POLICY_VERSION = "untrusted-content-gate-v1"
DANGEROUS_TARGETS = frozenset({"execute", "repo_or_file_write", "memory_or_skill"})


class SourceKind(StrEnum):
    TRUSTED_LOCAL = "trusted_local"
    USER_SUPPLIED_FILE = "user_supplied_file"
    PUBLIC_WEB = "public_web"
    PRIVATE_WEB = "private_web"
    EXTERNAL_REPO = "external_repo"
    REVIEWED_BUNDLE_SAFE = "reviewed_bundle_safe"
    REVIEWED_BUNDLE_SUSPICIOUS = "reviewed_bundle_suspicious"
    BLOCKED_OR_UNKNOWN = "blocked_or_unknown"


class TargetAction(StrEnum):
    READ_ONLY_SUMMARIZE = "read_only_summarize"
    DURABLE_OUTPUT = "durable_output"
    TASK_CREATE = "task_create"
    EXECUTE = "execute"
    REPO_OR_FILE_WRITE = "repo_or_file_write"
    MEMORY_OR_SKILL = "memory_or_skill"


@dataclass(frozen=True)
class ContentProvenance:
    source_kind: SourceKind | str
    origin_label: str = ""
    digest: str | None = None
    quarantine_bundle_id: str | None = None
    review_result: ReviewResult | str | None = None
    sanitized_ref: str | None = None

    def normalized_source_kind(self) -> SourceKind:
        return _source_kind(self.source_kind)


@dataclass(frozen=True)
class GateDecision:
    level: GateLevel
    reason: str
    source_kind: str
    target_action: str
    risk_metadata: dict[str, Any] = field(default_factory=dict)
    sanitized_value: Any = None
    bundle_ref: str | None = None
    broker_review_allowed: bool = False

    @property
    def allowed(self) -> bool:
        return self.level in {"allow", "warn"}


class UntrustedContentGateRefusal(RuntimeError):
    def __init__(self, decision: GateDecision):
        self.decision = decision
        super().__init__(f"untrusted content gate refused transition: {decision.level} ({decision.reason})")


def _source_kind(value: SourceKind | str) -> SourceKind:
    if isinstance(value, SourceKind):
        return value
    try:
        return SourceKind(str(value))
    except ValueError as exc:
        raise ValueError(f"unknown untrusted-content source_kind: {value!r}") from exc


def _target_action(value: TargetAction | str) -> TargetAction:
    if isinstance(value, TargetAction):
        return value
    try:
        return TargetAction(str(value))
    except ValueError as exc:
        raise ValueError(f"unknown untrusted-content target_action: {value!r}") from exc


def _risk_metadata(source: SourceKind, target: TargetAction, *, review_result: str | None = None, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "source_kind": source.value,
        "target_action": target.value,
    }
    if review_result:
        metadata["review_result"] = review_result
    if extra:
        metadata.update({str(k): v for k, v in extra.items() if v is not None})
    return metadata


def _decision(
    level: GateLevel,
    reason: str,
    source: SourceKind,
    target: TargetAction,
    *,
    review_result: str | None = None,
    broker_review_allowed: bool = False,
    risk_metadata: Mapping[str, Any] | None = None,
    sanitized_value: Any = None,
    bundle_ref: str | None = None,
) -> GateDecision:
    return GateDecision(
        level=level,
        reason=reason,
        source_kind=source.value,
        target_action=target.value,
        risk_metadata=_risk_metadata(source, target, review_result=review_result, extra=risk_metadata),
        sanitized_value=sanitized_value,
        bundle_ref=bundle_ref,
        broker_review_allowed=broker_review_allowed,
    )


def _review_result_decision(source: SourceKind, target: TargetAction, result: str) -> GateDecision | None:
    normalized = str(result).strip().casefold().replace("_", "-")
    if normalized in {"reviewer-failed", "failed", "failure", "error"}:
        if target.value in DANGEROUS_TARGETS or target is TargetAction.TASK_CREATE:
            return _decision("needs-human", "reviewer-failed-dangerous-transition", source, target, review_result="reviewer_failed")
        return _decision("warn", "reviewer-failed-read-only-degraded", source, target, review_result="reviewer_failed")
    if normalized == "safe":
        if target.value in DANGEROUS_TARGETS:
            return _decision("warn", "reviewed-safe-dangerous-transition", source, target, review_result="safe")
        return _decision("allow", "reviewed-safe", source, target, review_result="safe")
    if normalized == "suspicious":
        if target.value in DANGEROUS_TARGETS or target is TargetAction.TASK_CREATE:
            return _decision("needs-human", "reviewed-suspicious-dangerous-transition", source, target, review_result="suspicious")
        return _decision("warn", "reviewed-suspicious-read-only-or-durable", source, target, review_result="suspicious")
    if normalized in {"blocked", "needs-human", "needs_human"}:
        level: GateLevel = "needs-human" if normalized in {"needs-human", "needs_human"} else "block"
        return _decision(level, f"reviewed-{normalized}", source, target, review_result=normalized)
    return None


# Matrix entries intentionally reflect only explicit gated transitions.  Normal
# tool calls without external provenance must not call this module.
_POLICY_MATRIX: dict[SourceKind, dict[TargetAction, tuple[GateLevel, str, bool]]] = {
    SourceKind.TRUSTED_LOCAL: {
        action: ("allow", "trusted-local", False) for action in TargetAction
    },
    SourceKind.USER_SUPPLIED_FILE: {
        TargetAction.READ_ONLY_SUMMARIZE: ("warn", "user-file-read-only-warning", False),
        TargetAction.DURABLE_OUTPUT: ("warn", "user-file-durable-output-risk-metadata", False),
        TargetAction.TASK_CREATE: ("review", "user-file-task-create-requires-review", True),
        TargetAction.EXECUTE: ("review", "user-file-execute-requires-review", True),
        TargetAction.REPO_OR_FILE_WRITE: ("review", "user-file-write-requires-review", True),
        TargetAction.MEMORY_OR_SKILL: ("review", "user-file-memory-or-skill-requires-review", True),
    },
    SourceKind.PUBLIC_WEB: {
        TargetAction.READ_ONLY_SUMMARIZE: ("warn", "public-web-read-only-warning", False),
        TargetAction.DURABLE_OUTPUT: ("warn", "public-web-durable-output-risk-metadata", False),
        TargetAction.TASK_CREATE: ("review", "public-web-raw-task-create-requires-review", True),
        TargetAction.EXECUTE: ("review", "public-web-execute-requires-review", True),
        TargetAction.REPO_OR_FILE_WRITE: ("review", "public-web-write-requires-review", True),
        TargetAction.MEMORY_OR_SKILL: ("review", "public-web-memory-or-skill-requires-review", True),
    },
    SourceKind.PRIVATE_WEB: {
        TargetAction.READ_ONLY_SUMMARIZE: ("needs-human", "private-web-read-only-needs-human", False),
        TargetAction.DURABLE_OUTPUT: ("warn", "private-web-durable-output-metadata-only", False),
        TargetAction.TASK_CREATE: ("review", "private-web-task-create-requires-review", True),
        TargetAction.EXECUTE: ("needs-human", "private-web-execute-needs-human", False),
        TargetAction.REPO_OR_FILE_WRITE: ("needs-human", "private-web-write-needs-human", False),
        TargetAction.MEMORY_OR_SKILL: ("needs-human", "private-web-memory-or-skill-needs-human", False),
    },
    SourceKind.EXTERNAL_REPO: {
        TargetAction.READ_ONLY_SUMMARIZE: ("warn", "external-repo-read-only-warning", False),
        TargetAction.DURABLE_OUTPUT: ("warn", "external-repo-durable-output-risk-metadata", False),
        TargetAction.TASK_CREATE: ("review", "external-repo-task-create-requires-review", True),
        TargetAction.EXECUTE: ("review", "external-repo-execute-requires-review", True),
        TargetAction.REPO_OR_FILE_WRITE: ("review", "external-repo-write-requires-review", True),
        TargetAction.MEMORY_OR_SKILL: ("review", "external-repo-memory-or-skill-requires-review", True),
    },
    SourceKind.REVIEWED_BUNDLE_SAFE: {
        TargetAction.READ_ONLY_SUMMARIZE: ("allow", "reviewed-safe-read-only", False),
        TargetAction.DURABLE_OUTPUT: ("allow", "reviewed-safe-durable-output", False),
        TargetAction.TASK_CREATE: ("allow", "reviewed-safe-task-create", False),
        TargetAction.EXECUTE: ("warn", "reviewed-safe-execute-provenance-required", False),
        TargetAction.REPO_OR_FILE_WRITE: ("warn", "reviewed-safe-write-provenance-required", False),
        TargetAction.MEMORY_OR_SKILL: ("warn", "reviewed-safe-memory-or-skill-provenance-required", False),
    },
    SourceKind.REVIEWED_BUNDLE_SUSPICIOUS: {
        TargetAction.READ_ONLY_SUMMARIZE: ("warn", "reviewed-suspicious-read-only", False),
        TargetAction.DURABLE_OUTPUT: ("warn", "reviewed-suspicious-durable-output", False),
        TargetAction.TASK_CREATE: ("warn", "reviewed-suspicious-task-create-bundle-ref-only", False),
        TargetAction.EXECUTE: ("needs-human", "reviewed-suspicious-execute-needs-human", False),
        TargetAction.REPO_OR_FILE_WRITE: ("needs-human", "reviewed-suspicious-write-needs-human", False),
        TargetAction.MEMORY_OR_SKILL: ("needs-human", "reviewed-suspicious-memory-or-skill-needs-human", False),
    },
    SourceKind.BLOCKED_OR_UNKNOWN: {
        TargetAction.READ_ONLY_SUMMARIZE: ("needs-human", "blocked-or-unknown-read-only-needs-human", False),
        TargetAction.DURABLE_OUTPUT: ("warn", "blocked-or-unknown-metadata-only-output", False),
        TargetAction.TASK_CREATE: ("block", "blocked-or-unknown-task-create-blocked", False),
        TargetAction.EXECUTE: ("block", "blocked-or-unknown-execute-blocked", False),
        TargetAction.REPO_OR_FILE_WRITE: ("block", "blocked-or-unknown-write-blocked", False),
        TargetAction.MEMORY_OR_SKILL: ("block", "blocked-or-unknown-memory-or-skill-blocked", False),
    },
}


def evaluate_transition(
    source_kind: SourceKind | str,
    target_action: TargetAction | str,
    *,
    review_result: ReviewResult | str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> GateDecision:
    """Evaluate the v1 source-kind × target-action policy matrix."""

    source = _source_kind(source_kind)
    target = _target_action(target_action)
    if review_result:
        reviewed = _review_result_decision(source, target, str(review_result))
        if reviewed:
            if metadata:
                return _decision(
                    reviewed.level,
                    reviewed.reason,
                    source,
                    target,
                    review_result=str(review_result),
                    broker_review_allowed=reviewed.broker_review_allowed,
                    risk_metadata={**reviewed.risk_metadata, **dict(metadata)},
                )
            return reviewed
    level, reason, broker_allowed = _POLICY_MATRIX[source][target]
    return _decision(level, reason, source, target, broker_review_allowed=broker_allowed, risk_metadata=metadata)


def sanitize_untrusted_text(value: Any, *, raw_sources: Sequence[str] = (), max_len: int = 1000) -> str:
    """Redact content before it is persisted in durable fields."""

    sanitized = sanitize_for_durable_kanban(value, raw_sources=raw_sources)
    if not isinstance(sanitized, str):
        sanitized = str(sanitized)
    assert_durable_kanban_safe(sanitized, raw_sources=raw_sources)
    return sanitized[:max_len]


def sanitize_untrusted_metadata(value: Any, *, raw_sources: Sequence[str] = ()) -> Any:
    """Redact metadata before it is embedded in durable Kanban fields."""

    sanitized = sanitize_for_durable_kanban(value, raw_sources=raw_sources)
    assert_durable_kanban_safe(sanitized, raw_sources=raw_sources)
    return sanitized


def gate_transition(
    content: Any,
    provenance: ContentProvenance,
    target_action: TargetAction | str,
    *,
    dry_run: bool = False,
    broker_allowed: bool = True,
    raw_sources: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> GateDecision:
    """Evaluate and sanitize a known untrusted-content transition."""

    source = provenance.normalized_source_kind()
    target = _target_action(target_action)
    provenance_sources = tuple(
        str(v)
        for v in (provenance.origin_label, provenance.quarantine_bundle_id, provenance.sanitized_ref)
        if v and len(str(v)) > 20
    )
    raw_sources = tuple(raw_sources or ()) + ((str(content),) if isinstance(content, str) else ()) + provenance_sources
    bundle_ref = provenance.sanitized_ref or provenance.quarantine_bundle_id
    safe_origin = sanitize_untrusted_text(provenance.origin_label, raw_sources=raw_sources) if provenance.origin_label else ""
    safe_bundle_ref = sanitize_untrusted_text(bundle_ref, raw_sources=raw_sources) if bundle_ref else None
    risk_meta = {
        "origin_label": safe_origin or None,
        "digest": provenance.digest,
        "bundle_id": safe_bundle_ref,
        **dict(metadata or {}),
    }
    risk_meta = sanitize_untrusted_metadata(risk_meta, raw_sources=raw_sources)
    decision = evaluate_transition(source, target, review_result=provenance.review_result, metadata=risk_meta)
    safe_value = sanitize_for_durable_kanban(content, raw_sources=raw_sources)
    assert_durable_kanban_safe(safe_value, raw_sources=raw_sources)
    if dry_run and decision.level in {"review", "needs-human"}:
        decision = _decision(
            "warn",
            f"dry-run:{decision.reason}",
            source,
            target,
            review_result=provenance.review_result,
            broker_review_allowed=decision.broker_review_allowed and broker_allowed,
            risk_metadata=decision.risk_metadata,
            sanitized_value=safe_value,
            bundle_ref=bundle_ref,
        )
    else:
        decision = GateDecision(
            level=decision.level,
            reason=decision.reason,
            source_kind=decision.source_kind,
            target_action=decision.target_action,
            risk_metadata=decision.risk_metadata,
            sanitized_value=safe_value,
            bundle_ref=bundle_ref,
            broker_review_allowed=decision.broker_review_allowed and broker_allowed,
        )
    return decision


def gate_or_raise(
    content: Any,
    provenance: ContentProvenance,
    target_action: TargetAction | str,
    *,
    dry_run: bool = False,
    broker_allowed: bool = True,
    raw_sources: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> GateDecision:
    """Return a decision for allowed/warn transitions; raise on review/block/human gates."""

    decision = gate_transition(
        content,
        provenance,
        target_action,
        dry_run=dry_run,
        broker_allowed=broker_allowed,
        raw_sources=raw_sources,
        metadata=metadata,
    )
    if decision.level not in {"allow", "warn"}:
        raise UntrustedContentGateRefusal(decision)
    return decision
