"""``hermes security`` subcommand parser.

Extracted verbatim from ``hermes_cli/main.py:main()`` (god-file Phase 2).
Handler injected to avoid importing ``main``.
"""

from __future__ import annotations

from typing import Callable


def build_security_parser(subparsers, *, cmd_security: Callable) -> None:
    """Attach the ``security`` subcommand to ``subparsers``."""
    # =========================================================================
    security_parser = subparsers.add_parser(
        "security",
        help="Supply-chain audit (OSV.dev) for venv, plugins, and MCP servers",
        description=(
            "On-demand vulnerability scan against OSV.dev. Covers the Hermes "
            "venv (installed PyPI dists), Python deps declared by plugins under "
            "~/.hermes/plugins/, and pinned npx/uvx MCP servers in config.yaml. "
            "Does NOT scan globally-installed packages or editor/browser extensions."
        ),
    )
    security_subparsers = security_parser.add_subparsers(
        dest="security_command",
        metavar="<subcommand>",
    )

    audit_parser = security_subparsers.add_parser(
        "audit",
        help="Run a one-shot supply-chain audit",
        description="Query OSV.dev for known vulnerabilities in installed components.",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable text",
    )
    audit_parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["low", "moderate", "high", "critical"],
        help="Exit non-zero when any finding meets this severity (default: critical)",
    )
    audit_parser.add_argument(
        "--skip-venv",
        action="store_true",
        help="Skip scanning the Hermes Python venv",
    )
    audit_parser.add_argument(
        "--skip-plugins",
        action="store_true",
        help="Skip scanning plugin requirements files",
    )
    audit_parser.add_argument(
        "--skip-mcp",
        action="store_true",
        help="Skip scanning pinned MCP servers in config.yaml",
    )
    review_parser = security_subparsers.add_parser(
        "review",
        help="Prepare brokered untrusted-content security reviews",
        description="Create a redacted quarantine bundle and optionally hand it to a trusted Kanban broker.",
    )
    review_subparsers = review_parser.add_subparsers(dest="review_command", metavar="<review-subcommand>", required=True)

    def add_review_source_args(parser):
        src = parser.add_mutually_exclusive_group(required=True)
        src.add_argument("--text", help="Inline text to place in the quarantine bundle")
        src.add_argument("--text-file", help="Local text file to read into the quarantine bundle")
        src.add_argument("--url", help="Public URL reference to review; private URLs are redacted and marked needs-human")
        src.add_argument("--image", help="Image path or public URL reference; not opened or OCR'd by this command")
        src.add_argument("--metadata", help="Metadata string to include after redaction")
        parser.add_argument("--source-label", default="", help="Optional sanitized source label")
        parser.add_argument("--allow-private-url", action="store_true", help="Do not fail on private URLs; still writes only redacted host class and needs-human")
        parser.add_argument("--quarantine-root", help="Override quarantine root for tests/manual isolation")
        parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    prepare_parser = review_subparsers.add_parser("prepare", help="Create a quarantine bundle and print manual reviewer command")
    add_review_source_args(prepare_parser)
    prepare_parser.set_defaults(func=cmd_security)

    kanban_parser = review_subparsers.add_parser("kanban", help="Create a trusted broker Kanban task for the quarantine bundle")
    add_review_source_args(kanban_parser)
    kanban_parser.add_argument("--title", default="Security review broker task", help="Sanitized broker task title")
    kanban_parser.add_argument("--parent", help="Optional parent Kanban task id")
    kanban_parser.add_argument("--broker-assignee", default="hermes-dev-worker", help="Trusted broker profile (not security-reviewer)")
    kanban_parser.set_defaults(func=cmd_security)

    broker_run_parser = review_subparsers.add_parser("broker-run", help="Run trusted broker review for an existing quarantine bundle")
    broker_run_parser.add_argument("--bundle-dir", required=True, help="Quarantine bundle directory")
    broker_run_parser.add_argument("--reviewer-profile", default=None, help="Optional reviewer profile to invoke; omitted uses the current profile with restricted reviewer toolsets")
    broker_run_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    broker_run_parser.set_defaults(func=cmd_security)

    audit_parser.set_defaults(func=cmd_security)
    review_parser.set_defaults(func=cmd_security)
    security_parser.set_defaults(func=cmd_security)
