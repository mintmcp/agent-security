Claude Secret Scan
===================

CLI wrapper for the Claude Code secret scanning hooks. Provides `claude-secret-scan`.

Usage:

  echo '{"hook_event_name":"UserPromptSubmit","prompt":"hello"}' | claude-secret-scan --mode=pre

See https://github.com/mintmcp/agent-security for source and docs.

