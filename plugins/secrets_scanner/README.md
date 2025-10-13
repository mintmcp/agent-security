# Secrets Scanner Plugin

Blocks sending secrets to Claude Code or Cursor by scanning inputs and outputs.

## Installation

### Claude Code Plugin Marketplace

Install via the [Claude Code plugin marketplace](https://www.anthropic.com/news/claude-code-plugins):

```bash
/plugin marketplace add mintmcp/agent-security
/plugin install secrets-scanner@agent-security
```

### PyPI

```bash
pipx install claude-secret-scan
# or
python3 -m pip install --user claude-secret-scan
```

For manual usage, run `secrets_scanner_hook.py` with `python3` via hooks.

## Behavior

- `PreToolUse` / Cursor `beforeReadFile`: blocks when secrets are detected.
- `UserPromptSubmit` / Cursor `beforeSubmitPrompt`: blocks when secrets are detected.
- `PostToolUse`: prints a warning (cannot block after execution).

Detected classes include common cloud credentials, source control tokens, webhook URLs, payment provider keys, private keys, and JWTs. See `PATTERNS` in `hooks/secrets_scanner_hook.py` for details.

## Configuration

- `MAX_SCAN_BYTES` (default 5 MB)
- `PATTERNS` (regex map for credential types)

Binary content is skipped using a simple heuristic.

## Testing

See `tests/read_hook_test.py` and `TESTING.md` for examples and guidance.

## Notes

- Regex detection is best-effort. Rotate real secrets immediately.
- No external dependencies. Uses only Python's built-in regexes and simple pattern matching.
- Runs completely locally. No code, prompts, or files leave your system.
- Curious how it works? See `hooks/secrets_scanner_hook.py` for the core implementation and patterns.
- Python 3.7+.

## License

Apache License 2.0. See `../../LICENSE`.

## Acknowledgements

Regex patterns were informed by or adapted from `detect-secrets` (Apache 2.0).
