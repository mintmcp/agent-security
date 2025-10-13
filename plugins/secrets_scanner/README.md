# Secrets Scanner Plugin

[![Tests](https://img.shields.io/badge/tests-159%20passing-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.7+-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

Secret scanner that blocks sensitive credentials before they are sent to Claude Code or Cursor. The hook is a single Python file with no third-party dependencies and can be installed through the marketplace or PyPI.

## What It Does

- Detects 35+ credential formats across cloud, version control, payment, and collaboration providers.
- Supports both Claude Code and Cursor using the same executable.
- Intercepts prompt submissions, file reads, and post-tool output (warn-only for post-tool paths).
- Skips large or binary payloads to avoid unnecessary overhead.
- Designed to be extended by editing a single regex map.

## Installation

### Via Marketplace (Recommended)

```bash
/plugin marketplace add mintmcp/agent-security
/plugin install secrets-scanner@agent-security
```

### Via PyPI (Legacy)

```bash
pipx install claude-secret-scan            # isolated install
python3 -m pip install --user claude-secret-scan  # user site-packages
```

For manual usage, copy `secrets_scanner_hook.py` into the target config directory and run it with `python3`.

## How It Works

| Hook Event | Trigger | Outcome | Supported Clients |
|------------|---------|---------|-------------------|
| `PreToolUse` / `beforeReadFile` | Prior to reading files | Blocks if secrets are present | Claude Code, Cursor |
| `UserPromptSubmit` / `beforeSubmitPrompt` | Before prompt submission | Blocks if secrets are present | Claude Code, Cursor |
| `PostToolUse` | After tool execution | Prints warning (cannot block) | Claude Code |

### Detected Secret Classes

- **Cloud**: AWS access/secret keys, Google API keys and OAuth tokens, Azure SAS tokens and storage connection strings
- **Source control**: GitHub and GitLab PATs, Bitbucket app passwords
- **Communication**: Slack tokens and webhooks, Discord bot/webhook tokens, Telegram bot tokens
- **Payments**: Stripe, Square, Shopify credentials
- **Miscellaneous**: npm and PyPI tokens, Twilio credentials, JWTs, PEM/OpenSSH/PGP private keys (including encrypted)

See `PATTERNS` inside `hooks/secrets_scanner_hook.py` for the complete set.

## Configuration

The scanner can be configured by modifying constants in `secrets_scanner_hook.py`:

- `MAX_SCAN_BYTES` - defaults to 5 MB; increase only if you can tolerate slower scans on large files
- `PATTERNS` - dictionary of secret patterns; extend to add new providers

Binary detection uses a simple heuristic and skips payloads with a high ratio of non-text bytes.

## Tools

### scan_directory.py

Recursive directory scanner for testing and fine-tuning secret detection. Scans all files in a directory tree and reports which files contain potential secrets, along with line numbers and detection types. Does NOT emit the actual secret values to avoid accidental exposure.

## Testing

See [TESTING.md](./TESTING.md) for comprehensive test documentation with 159 test cases covering all supported credential formats.

## Operational Considerations

- Regex matching is best-effort. Treat detections as guardrails, not proof of exposure, and rotate any real secrets immediately.
- Post-tool hooks only warn; the tool has already executed by the time the hook runs.
- The scanner is I/O bound but typically completes in under 100 ms for common file sizes.
- Supports Python 3.7 and later. No external packages are required.

## License

Apache License 2.0. See [LICENSE](../../LICENSE) for the full text.

## Acknowledgements

Portions of the denylist regular expressions were informed by or adapted from the detect-secrets project (https://github.com/Yelp/detect-secrets), which is licensed under Apache 2.0.
