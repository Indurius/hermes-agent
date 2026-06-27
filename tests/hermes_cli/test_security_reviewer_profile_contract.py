from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli.security_review_broker import build_reviewer_command, reviewer_subprocess_env
from hermes_cli.security_review_cli import create_broker_task
from hermes_cli.security_review_gate import ReviewInput, SecurityReviewRefusal, prepare_review_bundle

def test_untrusted_content_security_review_skill_is_bundled():
    repo_root = Path(__file__).resolve().parents[2]
    skill_path = repo_root / "skills" / "software-development" / "untrusted-content-security-review" / "SKILL.md"
    assert skill_path.exists()
    content = skill_path.read_text()
    assert "Return exactly one JSON object" in content
    assert '"risk_class"' in content


def test_broker_command_does_not_pass_kanban_worker_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_bad")
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", "/tmp/bad")
    env = reviewer_subprocess_env()
    assert "HERMES_KANBAN_TASK" not in env
    assert "HERMES_KANBAN_WORKSPACE" not in env
    cmd = build_reviewer_command(tmp_path)
    assert "--profile" not in cmd
    assert "-t" in cmd
    assert "file,web,vision,skills" in cmd


def test_kanban_command_rejects_security_reviewer_as_broker_assignee(tmp_path):
    bundle = prepare_review_bundle([ReviewInput(kind="text", value="x")], quarantine_root=tmp_path)
    with pytest.raises(SecurityReviewRefusal):
        create_broker_task(bundle, title="Review", broker_assignee="security-reviewer")


def test_no_create_task_call_uses_security_reviewer_assignee_for_untrusted_content(monkeypatch, tmp_path):
    calls = []
    bundle = prepare_review_bundle([ReviewInput(kind="text", value="untrusted")], quarantine_root=tmp_path)
    monkeypatch.setattr("hermes_cli.security_review_cli.kb.connect_closing", lambda: _FakeConn())
    monkeypatch.setattr("hermes_cli.security_review_cli.kb.create_task", lambda conn, **kw: calls.append(kw) or "t_x")
    create_broker_task(bundle, title="Review", broker_assignee="hermes-dev-worker")
    assert all(call["assignee"] != "security-reviewer" for call in calls)
    assert all("untrusted-content-security-review" not in call.get("skills", []) for call in calls)


class _FakeConn:
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
