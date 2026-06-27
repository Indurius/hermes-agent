# Brokered Security Review Gate

Hermes can prepare untrusted text, URL references, images, or metadata for a contained review by a restricted reviewer subprocess using the bundled `untrusted-content-security-review` skill.

The MVP is explicit CLI only. It does not install global hooks in web extraction, file tools, browser, gateway attachments, Signal, or Home Assistant.

## Commands

Prepare a local quarantine bundle and print the manual reviewer command:

```bash
hermes security review prepare --text-file ./page.md
hermes security review prepare --url https://example.com/article
hermes security review prepare --text "pasted content" --source-label pasted-text
hermes security review prepare --image ./screenshot.png
```

Create a trusted Kanban broker task:

```bash
hermes security review kanban --text-file ./page.md --title "Review external content before summary"
hermes security review kanban --url https://example.com --parent t_12345678
```

`kanban` creates a task for the trusted broker assignee (`hermes-dev-worker` by default), not for `security-reviewer`.

## Trust boundary

```text
caller
  -> hermes security review prepare|kanban
  -> deterministic sanitizer + quarantine bundle
  -> trusted broker Kanban task
  -> hermes chat -Q -t file,web,vision,skills -s untrusted-content-security-review ...
  -> full output stays in the quarantine bundle
  -> Kanban receives only risk class + redacted summary + local output path
```

The reviewer is invoked as a normal CLI subprocess. The broker strips inherited `HERMES_KANBAN_*` environment variables so the reviewer does not become a Kanban worker.

## Automatic gating

The gate is only called at explicit, call-site scoped entry points. It is not a transparent global hook.

Automatic evaluation currently happens when:

- `hermes kanban create` is given `--external-source-kind ...`
- a reviewed external source is passed with `--external-reviewed-risk ...`
- `hermes security review prepare|kanban|broker-run` is invoked explicitly

`--gate-dry-run` keeps the same sanitation path but prefers `warn`/sanitized output where the policy allows it instead of hard failing safe transitions.

## Policy matrix

| Source | read-only summarize | durable output | task_create | execute / write / memory |
|---|---|---|---|---|
| `trusted_local` | allow | allow | allow | allow |
| `user_supplied_file` | warn | warn | review | review |
| `public_web` | warn | warn | review | review |
| `private_web` | needs-human | warn | review | needs-human |
| `external_repo` | warn | warn | review | review |
| `reviewed_bundle_safe` | allow | allow | allow | warn |
| `reviewed_bundle_suspicious` | warn | warn | warn | needs-human |
| `blocked_or_unknown` | needs-human | warn | block | block |

Review results may refine the matrix:

- `safe` allows more reads and task creation, but still keeps dangerous transitions on a short leash.
- `suspicious` usually becomes `needs-human` for dangerous transitions.
- `blocked` and `needs-human` remain fail-closed.
- `reviewer_failed` must not silently open dangerous transitions; it degrades read-only flows to `warn` or `needs-human` and keeps dangerous actions fail-closed.

## What is not gated

- normal local content without external provenance flags
- standard web/file/browser/gateway/Signal/Home Assistant tool calls without explicit gate metadata
- direct dispatch of the reviewer subprocess as a Kanban worker
- global transparent hooks in the MVP

## Quarantine bundle

Bundles live under:

```text
<kanban-home>/security-reviews/quarantine/<timestamp>-<random-token>/
```

The directory name is random and never derived from URLs, filenames, task titles, or content.

Allowed files include `manifest.json`, `metadata.json`, optional `content.txt`, optional `links.txt`, `review-prompt.txt`, `review-output.md`, and `broker-result.json`.

## Redaction policy

Durable Kanban fields may contain only:

- bundle id
- local bundle path under the quarantine root
- input kind / default risk hint
- risk class: `safe`, `suspicious`, `blocked`, or `needs-human`
- short sanitized summary
- local `review-output.md` path

Kanban must not contain raw content snippets, private fetchable URLs, secret-looking paths, tokens, or evidence quotes.

Private/internal URLs are never fetched by this gate. They are replaced with classes such as `private-url-redacted:localhost`, `private-url-redacted:rfc1918`, or `private-url-redacted:tailscale` and default to `needs-human`. `--allow-private-url` only permits creating that redacted `needs-human` bundle; it does not write the private URL.

## Limitations

This is not a malware sandbox, not a guarantee, and not a substitute for deterministic policy checks. The LLM reviewer can miss issues or produce ambiguous output; ambiguous or quote-heavy output must fail closed to `needs-human`.

## Rollback

This MVP is CLI-only. Revert the files under `hermes_cli/security_review_*`, the `hermes_cli/subcommands/security.py` parser changes, related tests, and this doc. Remove only generated directories under the quarantine root if cleanup is needed. No gateway, Signal, or Home Assistant restart is required.
