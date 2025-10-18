Claude Secret Scan
==================

Secret scanning CLI for Claude Code. Blocks or warns on common credentials (cloud, source control, payment, collaboration) using zero dependencies and local regex matching.

![Claude Secret Scan demo](https://github.com/mintmcp/agent-security/raw/main/assets/Claude-Secret-Scan.gif)

Why
- Prevent accidental leakage in everyday editor/agent workflows.
- Zero dependencies, single-file core, runs locally only.
- Simple to set up; easy for teams to adopt.

Install
- pipx (recommended):
  - `pipx install claude-secret-scan`
- pip (user):
  - `python3 -m pip install --user claude-secret-scan`

Hook Setup (Claude Code)
Add to `~/.claude/settings.json` for manual hooks:

```
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

CLI Usage
- Pre mode (blocks on detection):
  - `echo '{"hook_event_name":"UserPromptSubmit","prompt":"hello"}' | claude-secret-scan --mode=pre`
- Post mode (warns on detection):
  - `echo '{"tool_input":{"tool_name":"bash"},"tool_response":{"stdout":"OPENAI_API_KEY=...T3BlbkFJ..."}}' | claude-secret-scan --mode=post`

How It Works
- Regex-based detection for common credentials: AWS, GitHub, GitLab, Stripe, Slack, Discord, Telegram, Google, OpenAI/Anthropic, JWT/keys, and more.
- Reads only from hook JSON input or file paths provided by the hook.
- Binary-aware scanning with size limits; local-only execution.

Notes
- Pre hooks block; post hooks print warnings.
- Regex detection is best-effort. Rotate any real secrets immediately.
- For plugin marketplace usage and more docs, see the repository.

Links
- Source, docs, and examples: https://github.com/mintmcp/agent-security
