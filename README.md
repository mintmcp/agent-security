<img width="642" height="106" alt="image" src="https://github.com/user-attachments/assets/9aee367d-3d66-491a-9e04-a67944cb1c4c" />

[![PyPI version](https://badge.fury.io/py/claude-secret-scan.svg)](https://badge.fury.io/py/claude-secret-scan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-success.svg)]()
[![CI](https://github.com/mintmcp/agent-security/workflows/CI/badge.svg)](https://github.com/mintmcp/agent-security/actions)
[![Downloads](https://pepy.tech/badge/claude-secret-scan)](https://pepy.tech/project/claude-secret-scan)

## Security plugins for Claude Code and Cursor
This repository currently provides a secrets scanner plugin.

## Motivation

Coding agents are powerful, but we've repeatedly seen them read and propagate sensitive data during everyday work. That can be acceptable for casual "vibe coding" experiments, but it's not acceptable for production software engineering. We built this to make accidental leakage much harder: a standalone, local-first scanner with minimal footprint (no external dependencies, regex-only), running as editor/agent hooks entirely on your machine, and easy to set up so teams can adopt it without friction.

![Claude Secret Scan demo](assets/Claude-Secret-Scan.gif)

## Install

### Claude Code Plugin Marketplace

Install via the [Claude Code plugin marketplace](https://www.anthropic.com/news/claude-code-plugins):

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
- No external dependencies. The scanner uses only Python's built-in regexes and simple pattern matching.
- Runs completely locally. No code, prompts, or files leave your system.
- Curious how it works? See `plugins/secrets_scanner/hooks/secrets_scanner_hook.py` for the core implementation and patterns.
- No telemetry by default. For org-wide visibility and governance (dashboards, metrics, alerting), see https://mintmcp.com.

## License

Apache License 2.0. See `LICENSE`.

## Acknowledgements

Regex patterns were informed by or adapted from `detect-secrets` (Apache 2.0).
