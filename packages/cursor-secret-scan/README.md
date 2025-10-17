Cursor Secret Scan
==================

CLI wrapper for the Cursor secret scanning hooks. Provides `cursor-secret-scan`.

Usage:

  echo '{"hook_event_name":"beforeSubmitPrompt","prompt":"hello"}' | cursor-secret-scan --mode=pre

Depends on `claude-secret-scan` for the core implementation.

