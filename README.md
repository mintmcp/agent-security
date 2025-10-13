# Agent Security Plugins

Security plugins for Claude Code and Cursor. This repository currently provides a secrets scanner plugin.

## Install

### Marketplace

```bash
/plugin marketplace add mintmcp/agent-security
/plugin install secrets-scanner@agent-security
```

### PyPI (manual hooks)

```bash
pipx install claude-secret-scan
# or
python3 -m pip install --user claude-secret-scan
```

Add hooks to `~/.claude/settings.json` if using PyPI:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {"hooks": [{"type": "command", "command": "claude-secret-scan --mode=pre"}]} 
    ],
    "PreToolUse": [
      {"matcher": "Read|read", "hooks": [{"type": "command", "command": "claude-secret-scan --mode=pre"}]}
    ],
    "PostToolUse": [
      {"matcher": "Read|read", "hooks": [{"type": "command", "command": "claude-secret-scan --mode=post"}]},
      {"matcher": "Bash|bash", "hooks": [{"type": "command", "command": "claude-secret-scan --mode=post"}]}
    ]
  }
}
```

### Cursor

Copy `examples/configs/cursor-hooks.json` to `~/.cursor/hooks.json` or configure similarly:

```json
{
  "version": 1,
  "hooks": {
    "beforeReadFile": [{"command": "cursor-secret-scan --mode=pre"}],
    "beforeSubmitPrompt": [{"command": "cursor-secret-scan --mode=pre"}]
  }
}
```

## Repository Layout

```
.
├── .claude-plugin/
│   └── marketplace.json
├── plugins/
│   └── secrets_scanner/
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── hooks/
│       │   ├── hooks.json
│       │   └── secrets_scanner_hook.py
│       ├── tests/
│       │   └── read_hook_test.py
│       ├── TESTING.md
│       └── README.md
├── examples/
│   └── configs/
├── pyproject.toml
└── README.md
```

## Notes

- Pre hooks block when secrets are detected. Post hooks print warnings.
- Regex-based detection is best-effort. Rotate any real secrets immediately.

## License

Apache License 2.0. See `LICENSE`.

## Acknowledgements

Regex patterns were informed by or adapted from `detect-secrets` (Apache 2.0).
