# Configuration Examples

This directory contains configuration examples for **PyPI installation only**.

## Marketplace Installation (Recommended)

If using the marketplace, no manual configuration is needed:

```bash
/plugin marketplace add mintmcp/agent-security
/plugin install secrets-scanner@agent-security
```

The plugin will automatically configure the necessary hooks.

## PyPI Installation (Manual Configuration)

If you installed via PyPI (`pipx install claude-secret-scan`), use these configuration examples:

### Claude Code

Copy or merge `claude-settings.json` into `~/.claude/settings.json`

### Cursor

Copy or merge `cursor-hooks.json` into `~/.cursor/hooks.json`
