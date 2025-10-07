# Secret Scanner Hooks for Claude Code & Cursor

[![Tests](https://img.shields.io/badge/tests-158%20passing-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.7+-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

Secret scanner that blocks sensitive credentials before they are sent to Claude Code or Cursor. The hook is a single Python file with no third-party dependencies and can be installed through PyPI or copied directly.

## What It Does

- Detects 40+ credential formats across cloud, version control, payment, and collaboration providers.
- Supports both Claude Code and Cursor using the same executable.
- Intercepts prompt submissions, file reads, and post-tool output (warn-only for post-tool paths).
- Skips large or binary payloads to avoid unnecessary overhead.
- Designed to be extended by editing a single regex map.

## Install

```bash
pipx install claude-secret-scan            # isolated install
python3 -m pip install --user claude-secret-scan  # user site-packages
```

For manual usage, copy `secrets_scanner_hook.py` into the target config directory and run it with `python3` as in the examples below.

## Configure the Editors

Reference configs live under `examples/configs/` if you prefer to copy them verbatim.

### Claude Code

1. Copy `examples/configs/claude-settings.json` to `~/.claude/settings.json` or merge the relevant blocks.
2. Ensure each hook entry invokes `claude-secret-scan`:

```json
{
  "hooks": {
    "UserPromptSubmit": [{
      "hooks": [{
        "type": "command",
        "command": "claude-secret-scan --mode=pre"
      }]
    }],
    "PreToolUse": [{
      "matcher": "Read|read",
      "hooks": [{
        "type": "command",
        "command": "claude-secret-scan --mode=pre"
      }]
    }],
    "PostToolUse": [
      {
        "matcher": "Read|read",
        "hooks": [{
          "type": "command",
          "command": "claude-secret-scan --mode=post"
        }]
      },
      {
        "matcher": "Bash|bash",
        "hooks": [{
          "type": "command",
          "command": "claude-secret-scan --mode=post"
        }]
      }
    ]
  }
}
```

### Cursor

1. Copy `examples/configs/cursor-hooks.json` to `~/.cursor/hooks.json` or merge as needed.
2. Each hook entry should invoke `cursor-secret-scan`:

```json
{
  "version": 1,
  "hooks": {
    "beforeReadFile": [{
      "command": "cursor-secret-scan --mode=pre"
    }],
    "beforeSubmitPrompt": [{
      "command": "cursor-secret-scan --mode=pre"
    }]
  }
}
```

## How It Works

| Hook Event | Trigger | Outcome | Supported Clients |
|------------|---------|---------|-------------------|
| `PreToolUse` / `beforeReadFile` | Prior to reading files | Blocks if secrets are present | Claude Code, Cursor |
| `UserPromptSubmit` / `beforeSubmitPrompt` | Before prompt submission | Blocks if secrets are present | Claude Code, Cursor |
| `PostToolUse` | After tool execution | Prints warning (cannot block) | Claude Code |

Representative secret classes:

- Cloud: AWS access/secret keys, Google API keys and OAuth tokens, GCP service-account emails, Azure SAS tokens.
- Source control: GitHub and GitLab PATs, Bitbucket app passwords.
- Communication: Slack tokens and webhooks, Discord bot/webhook tokens, Telegram bot tokens.
- Payments: Stripe, Square, Shopify credentials.
- Miscellaneous: npm and PyPI tokens, Twilio credentials, JWTs, PEM/OpenSSH/PGP private keys.

See `PATTERNS` in `secrets_scanner/patterns.py` for the complete set.

## Configuration Notes

- `MAX_SCAN_BYTES` defaults to 5 MB; increase only if you can tolerate slower scans on large files.
- Binary detection uses a simple heuristic and skips payloads with a high ratio of non-text bytes.
- To add providers, extend the `PATTERNS` dictionary and keep test cases in sync.
- Manual installation: point the hooks to `python3 /path/to/secrets_scanner_hook.py --mode=... --client=...` if you do not want to install from PyPI.

## Repository Layout

```
.
├── examples/
│   └── configs/
│       ├── claude-settings.json
│       └── cursor-hooks.json
├── secrets_scanner_hook.py
├── pyproject.toml
├── read_hook_test.py
├── test-env.txt
└── README.md
```

## Operational Considerations

- Regex matching is best-effort. Treat detections as guardrails, not proof of exposure, and rotate any real secrets immediately.
- Post-tool hooks only warn; the tool has already executed by the time the hook runs.
- The scanner is I/O bound but typically completes in under 100 ms for common file sizes.
- Supports Python 3.7 and later. No external packages are required.

## License

Apache License 2.0. See `LICENSE` for the full text.
