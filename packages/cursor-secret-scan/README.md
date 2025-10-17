Cursor Secret Scan
==================

Secret scanning CLI for Cursor. Blocks or warns on common credentials (cloud, source control, payment, collaboration) using zero dependencies and local regex matching. Thin wrapper that depends on `claude-secret-scan`.

![Claude Code blocked from reading .env file with secrets](https://github.com/mintmcp/agent-security/raw/main/assets/claude-blocked.png)

Install
- pipx (recommended):
  - `pipx install cursor-secret-scan`
- pip (user):
  - `python3 -m pip install --user cursor-secret-scan`

Hook Setup (Cursor)
Add to `~/.cursor/hooks.json`:

```
{
  "version": 1,
  "hooks": {
    "beforeReadFile": [{"command": "cursor-secret-scan --mode=pre"}],
    "beforeSubmitPrompt": [{"command": "cursor-secret-scan --mode=pre"}]
  }
}
```

CLI Usage
- Pre mode (blocks on detection):
  - `echo '{"hook_event_name":"beforeSubmitPrompt","prompt":"hello"}' | cursor-secret-scan --mode=pre`
- Post mode (warns on detection):
  - `echo '{"hook_event_name":"afterShellExecution","stdout":"OPENAI_API_KEY=...T3BlbkFJ..."}' | cursor-secret-scan --mode=post`

How It Works
- Uses the same core regex-based scanner as `claude-secret-scan`.
- Reads only from hook JSON input or file paths provided by the hook.
- Binary-aware scanning with size limits; local-only execution.

Notes
- Pre hooks block; post hooks print warnings.
- Regex detection is best-effort. Rotate any real secrets immediately.

Links
- Source, docs, and examples: https://github.com/mintmcp/agent-security
