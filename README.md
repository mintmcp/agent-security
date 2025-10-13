# Agent Security Plugins

[![Python](https://img.shields.io/badge/python-3.7+-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

Security plugin marketplace for AI agents including Claude Code and Cursor. Provides defensive security tools including secret detection, security pattern warnings, and safe coding practices.

## Available Plugins

### Secrets Scanner

Detects 35+ credential formats across cloud, version control, payment, and collaboration providers. Blocks sensitive credentials before they are sent to Claude Code or Cursor.

**Key Features:**
- Comprehensive test coverage with 159 test cases
- Intercepts prompt submissions, file reads, and tool outputs
- No third-party dependencies
- Python 3.7+ compatible

[→ View Plugin README](./plugins/secrets_scanner/README.md)

## Quick Start

### Installation via Marketplace (Recommended)

```bash
# Add the marketplace
/plugin marketplace add mintmcp/agent-security

# Install the secrets scanner plugin
/plugin install secrets-scanner@agent-security
```

The plugin will automatically configure the necessary hooks for Claude Code.

### Legacy Installation via PyPI

For backward compatibility, the secrets scanner is still available via PyPI:

```bash
pipx install claude-secret-scan            # isolated install
python3 -m pip install --user claude-secret-scan  # user site-packages
```

Then manually configure hooks in `~/.claude/settings.json`:

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

## Cursor Support

For Cursor users, copy `examples/configs/cursor-hooks.json` to `~/.cursor/hooks.json` or install via PyPI and configure manually:

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

## Repository Structure

```
.
├── .claude-plugin/
│   └── marketplace.json          # Marketplace catalog
├── plugins/
│   └── secrets_scanner/
│       ├── .claude-plugin/
│       │   └── plugin.json       # Plugin metadata
│       ├── hooks/
│       │   ├── hooks.json        # Hook configuration
│       │   └── secrets_scanner_hook.py
│       ├── tools/
│       │   └── scan_directory.py # Testing utility
│       ├── tests/
│       │   └── read_hook_test.py # Comprehensive tests
│       ├── TESTING.md
│       └── README.md
├── examples/
│   └── configs/                  # Legacy configuration examples
├── pyproject.toml                # PyPI package metadata
└── README.md
```

## Migrating from v0.1.x

If you previously installed using PyPI (`pipx install claude-secret-scan`), your existing setup will continue to work. No changes are required.

To use the new marketplace installation:
1. Remove old hooks from `~/.claude/settings.json` (optional)
2. Add the marketplace: `/plugin marketplace add mintmcp/agent-security`
3. Install plugin: `/plugin install secrets-scanner@agent-security`

## Contributing

We welcome contributions! To add a new security plugin:

1. Create a new directory under `plugins/your-plugin-name/`
2. Follow the structure of existing plugins:
   - `.claude-plugin/plugin.json` - Plugin metadata
   - `hooks/hooks.json` - Hook configuration
   - `hooks/your_hook.py` - Hook implementation
   - `README.md` - Plugin documentation
3. Add your plugin to `.claude-plugin/marketplace.json`
4. Submit a pull request

## Plugin Development

Each plugin should be self-contained with:
- Clear documentation of what it detects/prevents
- Comprehensive test coverage
- Zero or minimal dependencies
- Python 3.7+ compatibility

See individual plugin READMEs for implementation details.

## Security Philosophy

These plugins provide **defensive security** guardrails:
- Detect and block sensitive data leakage
- Warn about insecure coding patterns
- Enforce security best practices

Regex matching is best-effort. Treat detections as guardrails, not proof of exposure, and rotate any real secrets immediately.

## License

Apache License 2.0. See [LICENSE](./LICENSE) for the full text.

## Acknowledgements

Portions of the denylist regular expressions were informed by or adapted from the [detect-secrets project](https://github.com/Yelp/detect-secrets), which is licensed under Apache 2.0.

---

**Maintained by [MintMCP](https://mintmcp.com)** | [Report Issues](https://github.com/mintmcp/agent-security/issues)
