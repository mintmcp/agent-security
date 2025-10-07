# 🔐 Secret Scanner Hooks for Claude Code & Cursor

[![Tests](https://img.shields.io/badge/tests-158%20passing-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.7+-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

A secret scanning hook that helps prevent sensitive credentials from being exposed to AI coding assistants. Works with both Claude Code and Cursor, with zero external dependencies.

## 🎯 Features

- **🛡️ Multi-Provider Detection** - Scans for 40+ secret types including AWS, GitHub, OpenAI, Stripe, Slack, and more
- **🔄 Dual Client Support** - Single codebase works with both Claude Code and Cursor
- **⚡ Real-time Protection** - Blocks secrets before file reads, command execution, and prompt submission
- **🧪 Thoroughly Tested** - 158 test cases covering edge cases, false positives, and both client formats
- **📦 Zero Dependencies** - Pure Python 3.7+ with no external packages required
- **🎨 Extensible** - Easy-to-modify regex patterns for custom secret detection

## 🚀 Quick Start

### Install

- Recommended (isolated): `pipx install claude-secret-scan`
- User-level install: `python3 -m pip install --user claude-secret-scan`
- Manual fallback: copy `secrets_scanner_hook.py` into the client config directory (see notes below).

Use `claude-secret-scan` (defaults to Claude Code formatting) and `cursor-secret-scan` to force Cursor formatting.

### Claude Code

1. **Add to `~/.claude/settings.json`:**
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

### Cursor

1. **Create `~/.cursor/hooks.json`:**
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

2. **Restart Cursor** and verify hooks are loaded in Settings → Hooks

## 📋 How It Works

### Protection Layers

| Hook Event | When | Action | Client Support |
|------------|------|--------|----------------|
| **PreToolUse** / **beforeReadFile** | Before reading files | ❌ **Blocks** file access if secrets detected | Both |
| **UserPromptSubmit** / **beforeSubmitPrompt** | Before sending prompts | ❌ **Blocks** submission if secrets in prompt | Both |
| **PostToolUse** | After tool execution | ⚠️ **Warns** if secrets in output (cannot block) | Claude Code only |

### Detected Secret Types

**Cloud Providers (6 types)**
- AWS Access Keys (AKIA, ASIA, AIDA, AROA, etc.)
- AWS Secret Access Keys
- Google API Keys (AIza...)
- Google OAuth Tokens (ya29...)
- GCP Service Accounts
- Azure Storage Connection Strings & SAS Tokens

**Version Control (4 types)**
- GitHub Personal Access Tokens (ghp_, gho_, ghs_, ghu_, ghr_)
- GitHub Fine-Grained PATs
- GitLab Personal Access Tokens
- Bitbucket App Passwords

**Communication & Collaboration (4 types)**
- Slack Tokens (xoxb, xoxp, xoxe, etc.)
- Slack Webhooks
- Discord Bot Tokens & Webhooks
- Telegram Bot Tokens

**AI & ML Providers (2 types)**
- OpenAI API Keys (sk-, sk-proj-)
- Databricks Personal Access Tokens

**Payment & E-commerce (6 types)**
- Stripe Secret Keys (live & test)
- Stripe Publishable Keys
- Square Access Tokens
- Shopify Tokens

**Other Services (18+ types)**
- Twilio Account SIDs & Auth Tokens
- SendGrid API Keys
- npm Tokens
- PyPI Tokens
- JWT Tokens
- Private Keys (PEM, OpenSSH, PGP)
- And many more...

[**See full pattern list →**](secrets_scanner_hook.py#L75-L160)

## 🧪 Testing

Run the comprehensive test suite to verify detection:

```bash
# Run all tests (both client types, all scenarios)
python3 read_hook_test.py --suite all

# Quick provider coverage test
python3 read_hook_test.py --suite basic

# Extended edge cases & formatting tests
python3 read_hook_test.py --suite extended
```

### Test Coverage

- ✅ **158 test cases** covering both Claude Code and Cursor formats
- ✅ **40+ secret providers** with positive & negative cases
- ✅ **Edge cases**: whitespace, quotes, URLs, comments, multi-line, base64
- ✅ **False positive prevention**: short strings, prefixes only, similar patterns

### Manual Testing

Test specific scenarios:

```bash
# Test file read with secrets
echo '{"tool_input": {"file_path": "./test-env.txt"}}' | \
  python3 secrets_scanner_hook.py --mode=pre --client=claude_code

# Test Cursor format
echo '{"hook_event_name": "beforeReadFile", "file_path": "./test.env", "content": "OPENAI_API_KEY=sk-test"}' | \
  python3 secrets_scanner_hook.py --mode=pre --client=cursor

# Test command output scanning
echo '{"tool_result": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}' | \
  python3 secrets_scanner_hook.py --mode=post --client=claude_code
```

## 🔧 Configuration

### File Size Limits

Files are scanned up to **5MB**. Binary files are automatically skipped.

```python
MAX_SCAN_BYTES = 5 * 1024 * 1024  # Adjust in secrets_scanner_hook.py
```

### Custom Patterns

Add new secret patterns to the `PATTERNS` dict in `secrets_scanner_hook.py`:

```python
PATTERNS = {
    # ... existing patterns ...

    "My Custom API Key": re.compile(r"\bmy_api_[A-Za-z0-9]{32}\b"),
}
```

**After adding patterns, run tests:**
```bash
python3 read_hook_test.py --suite extended
```

### Manual Installation

If you prefer not to use `pip` or `pipx`, copy `secrets_scanner_hook.py` into the appropriate client directory and update the JSON examples above to point to `python3 ~/.claude/secrets_scanner_hook.py ...` (Claude Code) or `python3 ~/.cursor/secrets_scanner_hook.py ...` (Cursor).

### Tool Matchers (Claude Code)

Customize which tools trigger scanning by updating matchers in `settings.json`:

```json
{
  "PostToolUse": [{
    "matcher": "Read|Edit|Write|Bash",  // Add more tool names
    "hooks": [...]
  }]
}
```

## 📁 Project Structure

```
.
├── secrets_scanner_hook.py   # Main hook script (works with both clients)
├── settings.json              # Claude Code hook configuration
├── hooks.json                 # Cursor hook configuration
├── pyproject.toml             # Packaging metadata for PyPI
├── read_hook_test.py          # Comprehensive test suite
├── test-env.txt               # Test file with sample secrets
└── README.md                  # This file
```

## ⚠️ Important Notes

### Security Considerations

- **🚨 Regex Limitations**: Pattern matching has false positives and negatives. Use as a guardrail, not absolute protection.
- **🔄 Rotate Exposed Secrets**: If secrets are detected, rotate them immediately.
- **📦 Use Secret Managers**: Store credentials in AWS Secrets Manager, HashiCorp Vault, etc.
- **👁️ Post-Tool Warnings Only**: `PostToolUse` hooks can only warn (tool already executed).

### Performance

- Binary files and files >5MB are skipped automatically
- Regex scanning is optimized for speed
- Minimal overhead on hook execution (<100ms for most files)

### Compatibility

- **Python**: 3.7+ (no external dependencies)
- **Claude Code**: Latest version with hooks support
- **Cursor**: Hook system enabled

## 🚢 Publishing

1. Bump the version in both `pyproject.toml` and `secrets_scanner_hook.py` (`__version__`).
2. Run the test suites: `python3 read_hook_test.py --suite all`.
3. Build artifacts: `python3 -m pip install --upgrade build twine` then `python3 -m build`.
4. Verify packages: `python3 -m twine check dist/*` and optionally `pipx install --spec dist/claude_secret_scan-<version>-py3-none-any.whl --suffix test`.
5. Upload to PyPI: `python3 -m twine upload dist/*` (or `--repository testpypi` for dry-runs).
6. Tag the release and attach the wheel/sdist to the GitHub release for checksum verification (`shasum -a 256 dist/*`).

## 🤝 Contributing

Contributions welcome! To add new secret patterns:

1. Add regex to `PATTERNS` dict in `secrets_scanner_hook.py`
2. Add test cases to `read_hook_test.py`
3. Run full test suite: `python3 read_hook_test.py --suite all`
4. Submit PR with pattern justification

## 📝 License

Apache License 2.0 - see LICENSE file for details

## 🙏 Acknowledgments

Built for safe AI-assisted development with Claude Code and Cursor.
