from __future__ import annotations

import argparse
import json

import pytest

from hermes_cli.security_review_cli import build_review_inputs, security_review_command
from hermes_cli.subcommands.security import build_security_parser


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_security_parser(sub, cmd_security=lambda args: args)
    return parser


def test_security_review_prepare_parser_accepts_text_file():
    args = _parser().parse_args(["security", "review", "prepare", "--text-file", "page.md"])
    assert args.security_command == "review"
    assert args.review_command == "prepare"
    assert args.text_file == "page.md"


def test_security_review_prepare_parser_accepts_public_url():
    args = _parser().parse_args(["security", "review", "prepare", "--url", "https://example.com"])
    assert args.url == "https://example.com"


def test_security_review_without_subcommand_still_defaults_to_audit():
    args = _parser().parse_args(["security"])
    assert args.security_command is None


def test_build_review_inputs_requires_one_source():
    args = argparse.Namespace(text=None, text_file=None, url=None, image=None, metadata=None, source_label="")
    with pytest.raises(SystemExit):
        build_review_inputs(args)


def test_prepare_command_prints_manual_reviewer_command_only(tmp_path, capsys):
    args = argparse.Namespace(
        review_command="prepare",
        text="hello bees",
        text_file=None,
        url=None,
        image=None,
        metadata=None,
        source_label="sample",
        allow_private_url=False,
        quarantine_root=str(tmp_path),
        json=False,
    )
    assert security_review_command(args) == 0
    out = capsys.readouterr().out
    assert "bundle:" in out
    assert "manual_review_command:" in out
    assert "untrusted-content-security-review" in out
    assert "file,web,vision,skills" in out
    assert "Created" not in out


def test_prepare_private_url_outputs_needs_human_without_url(tmp_path, capsys):
    args = argparse.Namespace(
        review_command="prepare",
        text=None,
        text_file=None,
        url="http://10.0.0.5/admin?token=x",
        image=None,
        metadata=None,
        source_label="router",
        allow_private_url=False,
        quarantine_root=str(tmp_path),
        json=True,
    )
    assert security_review_command(args) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["default_risk"] == "needs-human"
    metadata = (tmp_path / data["bundle_id"] / "metadata.json").read_text()
    assert "10.0.0.5" not in metadata
    assert "token=x" not in metadata
