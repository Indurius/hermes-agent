"""Trusted broker runner for the security-reviewer profile."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.redact import redact_sensitive_text

from hermes_cli.security_review_gate import (
    RISK_CLASSES,
    SecurityReviewRefusal,
    assert_durable_kanban_safe,
    build_reviewer_prompt,
    default_quarantine_root,
    sanitize_for_durable_kanban,
)


@dataclass(frozen=True)
class BrokerResult:
    risk_class: str
    bundle_id: str
    review_output_path: Path
    sanitized_summary: str
    allowed_next_step: str
    blocked_reason: str

    def as_kanban_handoff(self) -> dict[str, Any]:
        return {
            "risk_class": self.risk_class,
            "bundle_id": self.bundle_id,
            "review_output_path": str(self.review_output_path),
            "sanitized_summary": self.sanitized_summary,
            "allowed_next_step": self.allowed_next_step,
            "blocked_reason": self.blocked_reason,
        }


REVIEWER_TOOLSETS = ("file", "web", "vision", "skills")


def build_reviewer_command(
    bundle_dir: Path,
    *,
    reviewer_profile: str | None = None,
    reviewer_toolsets: tuple[str, ...] = REVIEWER_TOOLSETS,
) -> list[str]:
    cmd = ["hermes"]
    if reviewer_profile:
        cmd.extend(["--profile", reviewer_profile])
    cmd.extend([
        "chat",
        "-Q",
        "-t",
        ",".join(reviewer_toolsets),
        "-s",
        "untrusted-content-security-review",
        "-q",
        build_reviewer_prompt(bundle_dir),
    ])
    return cmd


def reviewer_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("HERMES_KANBAN_"):
            env.pop(key, None)
    env.pop("HERMES_KANBAN_TASK", None)
    env.pop("HERMES_KANBAN_WORKSPACE", None)
    return env


def _load_manifest(bundle_dir: Path) -> dict[str, Any]:
    path = bundle_dir / "manifest.json"
    if not path.exists():
        raise SecurityReviewRefusal("security review bundle is missing manifest.json")
    try:
        manifest = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SecurityReviewRefusal("security review manifest is not valid JSON") from exc
    if not manifest.get("bundle_id"):
        raise SecurityReviewRefusal("security review manifest is missing bundle_id")
    return manifest


def _verify_bundle_dir(bundle_dir: Path, manifest: dict[str, Any]) -> Path:
    bundle_dir = bundle_dir.expanduser().resolve()
    root_text = manifest.get("quarantine_root") or str(default_quarantine_root())
    root = Path(str(root_text)).expanduser().resolve()
    try:
        bundle_dir.relative_to(root)
    except ValueError as exc:
        raise SecurityReviewRefusal("security review bundle is outside quarantine root") from exc
    manifest_dir = Path(str(manifest.get("bundle_dir", bundle_dir))).expanduser().resolve()
    if manifest_dir != bundle_dir:
        raise SecurityReviewRefusal("security review manifest bundle_dir does not match workspace")
    return bundle_dir


def _ambiguous_reviewer_result(*, bundle_id: str, review_output_path: Path, stdout: str, reason: str) -> BrokerResult:
    raw_sources: list[str] = []
    summary = str(
        sanitize_for_durable_kanban(
            "Reviewer output was ambiguous; human review required.",
            raw_sources=raw_sources,
        )
    )[:300]
    result = BrokerResult(
        "needs-human",
        bundle_id,
        review_output_path,
        summary,
        "needs-human",
        reason,
    )
    assert_durable_kanban_safe(result.as_kanban_handoff(), raw_sources=raw_sources)
    return result


def _parse_reviewer_json(stdout: str) -> dict[str, Any] | None:
    text = stdout.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text.removeprefix("```json").removesuffix("```").strip()
    elif text.startswith("```") and text.endswith("```"):
        text = text.removeprefix("```").removesuffix("```").strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _derive_result(stdout: str, *, bundle_id: str, review_output_path: Path) -> BrokerResult:
    payload = _parse_reviewer_json(stdout)
    if payload is None:
        return _ambiguous_reviewer_result(
            bundle_id=bundle_id,
            review_output_path=review_output_path,
            stdout=stdout,
            reason="reviewer-output-not-strict-json",
        )
    risk = str(payload.get("risk_class") or "").strip().lower()
    if risk not in RISK_CLASSES:
        return _ambiguous_reviewer_result(
            bundle_id=bundle_id,
            review_output_path=review_output_path,
            stdout=stdout,
            reason="reviewer-output-invalid-risk-class",
        )
    summary = str(payload.get("sanitized_summary") or "")
    allowed = str(payload.get("allowed_next_step") or ("continue" if risk == "safe" else "needs-human"))
    blocked = str(payload.get("blocked_reason") or ("none" if risk == "safe" else "reviewer-classified-risk"))
    if not summary.strip():
        return _ambiguous_reviewer_result(
            bundle_id=bundle_id,
            review_output_path=review_output_path,
            stdout=stdout,
            reason="reviewer-output-missing-summary",
        )
    raw_sources = [summary]
    summary = str(sanitize_for_durable_kanban(summary, raw_sources=raw_sources))[:300]
    allowed = str(sanitize_for_durable_kanban(allowed, raw_sources=raw_sources))[:200]
    blocked = str(sanitize_for_durable_kanban(blocked, raw_sources=raw_sources))[:200]
    result = BrokerResult(risk, bundle_id, review_output_path, summary, allowed, blocked)
    assert_durable_kanban_safe(result.as_kanban_handoff(), raw_sources=raw_sources)
    return result


def run_broker_review(bundle_dir: Path, *, reviewer_profile: str | None = None, timeout: int = 300) -> BrokerResult:
    manifest = _load_manifest(bundle_dir)
    bundle_dir = _verify_bundle_dir(bundle_dir, manifest)
    cmd = build_reviewer_command(bundle_dir, reviewer_profile=reviewer_profile)
    completed = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=reviewer_subprocess_env(),
    )
    output = completed.stdout or ""
    if completed.stderr:
        output += "\n\n[stderr]\n" + completed.stderr
    output = redact_sensitive_text(output, force=True)
    review_output_path = bundle_dir / "review-output.md"
    review_output_path.write_text(output)
    if completed.returncode != 0:
        raw_sources = [output]
        summary = str(
            sanitize_for_durable_kanban(
                "security-reviewer subprocess failed; human review required.",
                raw_sources=raw_sources,
            )
        )[:300]
        result = BrokerResult(
            "needs-human",
            str(manifest["bundle_id"]),
            review_output_path,
            summary,
            "needs-human",
            "reviewer-subprocess-failed",
        )
        assert_durable_kanban_safe(result.as_kanban_handoff(), raw_sources=raw_sources)
    else:
        result = _derive_result(output, bundle_id=str(manifest["bundle_id"]), review_output_path=review_output_path)
    (bundle_dir / "broker-result.json").write_text(json.dumps(result.as_kanban_handoff(), indent=2, sort_keys=True))
    return result
