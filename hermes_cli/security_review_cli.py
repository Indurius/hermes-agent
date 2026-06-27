"""CLI commands for brokered untrusted-content security reviews."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from hermes_cli import kanban_db as kb
from hermes_cli.security_review_gate import (
    MAX_TEXT_BYTES,
    ReviewBundle,
    ReviewInput,
    SecurityReviewRefusal,
    assert_durable_kanban_safe,
    dumps_durable_json,
    prepare_review_bundle,
    sanitize_for_durable_kanban,
)

BROKER_SKILLS = ["hermes-agent", "systematic-debugging"]
DEFAULT_BROKER_ASSIGNEE = "hermes-dev-worker"


def build_review_inputs(args: argparse.Namespace) -> list[ReviewInput]:
    values = [
        ("text", getattr(args, "text", None)),
        ("text_file", getattr(args, "text_file", None)),
        ("url", getattr(args, "url", None)),
        ("image", getattr(args, "image", None)),
        ("metadata", getattr(args, "metadata", None)),
    ]
    inputs = [ReviewInput(kind=kind, value=value, source_label=getattr(args, "source_label", "") or "") for kind, value in values if value]
    if not inputs:
        raise SystemExit("security review: one of --text, --text-file, --url, --image, or --metadata is required")
    return inputs


def _quarantine_root_from_args(args: argparse.Namespace) -> Path | None:
    root = getattr(args, "quarantine_root", None)
    return Path(root).expanduser() if root else None


def collect_kanban_raw_sources(args: argparse.Namespace) -> list[str]:
    sources: list[str] = []
    for attr in ("text", "url", "image", "metadata", "source_label"):
        value = getattr(args, attr, None)
        if value:
            sources.append(str(value))
    text_file = getattr(args, "text_file", None)
    if text_file:
        path = Path(str(text_file)).expanduser()
        sources.append(path.name)
        try:
            sources.append(path.read_bytes()[: MAX_TEXT_BYTES + 1].decode("utf-8", errors="replace"))
        except OSError:
            # prepare_review_bundle already validated/read the source when possible;
            # do not fail Kanban redaction collection solely because it changed.
            pass
    return sources


def create_broker_task(
    bundle: ReviewBundle,
    *,
    title: str,
    broker_assignee: str = DEFAULT_BROKER_ASSIGNEE,
    parent: str | None = None,
    raw_sources: Sequence[str] = (),
) -> str:
    broker_assignee = (broker_assignee or DEFAULT_BROKER_ASSIGNEE).strip()
    if broker_assignee.casefold() == "security-reviewer":
        raise SecurityReviewRefusal("security-reviewer must not be used as a Kanban broker for untrusted content")
    body_payload = {
        "kind": "security_review_broker",
        "bundle_id": bundle.bundle_id,
        "bundle_dir": str(bundle.bundle_dir),
        "default_risk": bundle.default_risk,
        "redaction_version": "security-review-gate-v1",
        "expected_output": {
            "risk_class": "safe|suspicious|blocked|needs-human",
            "sanitized_summary": "max 300 chars, no quotes from raw content",
            "allowed_next_step": "sanitized paraphrase or enum",
            "blocked_reason": "sanitized paraphrase or enum",
        },
        "broker_instruction": "Invoke `hermes security review broker-run --bundle-dir ...` against the local quarantine bundle. Do not copy raw content into Kanban.",
    }
    safe_title = sanitize_for_durable_kanban(title or "Security review broker task", raw_sources=raw_sources)
    body = dumps_durable_json(body_payload, raw_sources=raw_sources)
    assert_durable_kanban_safe(safe_title, raw_sources=raw_sources)
    assert_durable_kanban_safe(body, raw_sources=raw_sources)
    with kb.connect_closing() as conn:
        return kb.create_task(
            conn,
            title=str(safe_title)[:120] or "Security review broker task",
            body=body,
            assignee=broker_assignee,
            workspace_kind="dir",
            workspace_path=str(bundle.bundle_dir),
            parents=[parent] if parent else [],
            skills=BROKER_SKILLS,
            initial_status="running",
        )


def _emit_prepare(bundle: ReviewBundle, *, as_json: bool) -> None:
    from hermes_cli.security_review_broker import build_reviewer_command

    command = build_reviewer_command(bundle.bundle_dir)
    if as_json:
        print(json.dumps({"bundle_id": bundle.bundle_id, "bundle": str(bundle.bundle_dir), "default_risk": bundle.default_risk, "manual_review_command": command}, indent=2))
        return
    print(f"bundle: {bundle.bundle_dir}")
    print(f"default_risk: {bundle.default_risk}")
    print("manual_review_command:")
    print("  " + " ".join(json.dumps(part) if " " in part else part for part in command))


def security_review_command(args: argparse.Namespace) -> int:
    sub = getattr(args, "review_command", None)
    try:
        if sub == "broker-run":
            from hermes_cli.security_review_broker import run_broker_review

            result = run_broker_review(Path(getattr(args, "bundle_dir")), reviewer_profile=getattr(args, "reviewer_profile", None))
            if getattr(args, "json", False):
                print(json.dumps(result.as_kanban_handoff(), indent=2, sort_keys=True))
            else:
                print(f"risk_class: {result.risk_class}")
                print(f"review_output_path: {result.review_output_path}")
                print(f"sanitized_summary: {result.sanitized_summary}")
            return 0
        bundle = prepare_review_bundle(
            build_review_inputs(args),
            allow_private_url=bool(getattr(args, "allow_private_url", False)),
            quarantine_root=_quarantine_root_from_args(args),
        )
        if sub == "prepare":
            _emit_prepare(bundle, as_json=bool(getattr(args, "json", False)))
            return 0
        if sub == "kanban":
            raw_sources = collect_kanban_raw_sources(args)
            task_id = create_broker_task(
                bundle,
                title=getattr(args, "title", None) or "Security review broker task",
                broker_assignee=getattr(args, "broker_assignee", None) or DEFAULT_BROKER_ASSIGNEE,
                parent=getattr(args, "parent", None),
                raw_sources=raw_sources,
            )
            if getattr(args, "json", False):
                print(json.dumps({"task_id": task_id, "bundle_id": bundle.bundle_id, "bundle": str(bundle.bundle_dir), "assignee": getattr(args, "broker_assignee", None) or DEFAULT_BROKER_ASSIGNEE}, indent=2))
            else:
                print(f"Created broker task {task_id} (assignee={getattr(args, 'broker_assignee', None) or DEFAULT_BROKER_ASSIGNEE})")
                print(f"bundle: {bundle.bundle_dir}")
            return 0
    except SecurityReviewRefusal as exc:
        print(f"security review: {exc}", file=sys.stderr)
        return 2
    raise SystemExit(f"unknown security review subcommand: {sub}")
