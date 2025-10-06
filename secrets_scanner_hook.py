#!/usr/bin/env python3
"""Secret scanner hook shared by Claude Code and Cursor.

Usage:
  secrets_scanner_hook.py --mode=pre
  secrets_scanner_hook.py --mode=post

Claude Code formats:
  PreToolUse:  {"toolInput": {"file_path": "..."}}
               Output: {"action": "allow|block", "message": "..."}
  PostToolUse: {"toolInput": {"file_path": "..."}, "toolResult": "..."}
               Output: {"action": "allow", "message": "..."}

Cursor formats:
  beforeReadFile: {"hook_event_name": "beforeReadFile", "file_path": "..."}
                  Output: {"allow": true|false, "message": "..."}
"""

import sys, json, os, re, argparse

MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5MB safety cap per file
SAMPLE_BYTES = 4096  # bytes sampled to determine if a file looks binary

USER_MESSAGE_KEYS = {
    "messages",
    "message",
    "text",
    "content",
    "input",
    "input_text",
    "prompt",
    "body",
    "segments",
    "user_message",
}

COMMAND_OUTPUT_KEYS = {
    "stdout",
    "stderr",
    "output",
    "content",
    "text",
    "message",
    "result",
    "body",
    "response",
    "value",
}

SUMMARY_LIMIT = 5

# ============================================================================
# SECRET SCANNER LOGIC
# ============================================================================

def is_probably_binary(block: bytes) -> bool:
    if b'\x00' in block: return True
    textchars = bytes(range(32, 127)) + b'\n\r\t\b'
    nontext = block.translate(None, textchars)
    return len(nontext) / max(1, len(block)) > 0.30

def should_scan_file(path: str) -> bool:
    """Return True when the target looks like text and should be scanned."""
    try:
        with open(path, "rb") as sample:
            head = sample.read(SAMPLE_BYTES)
    except OSError:
        return False

    if not head:
        return True

    return not is_probably_binary(head)

PATTERNS = {
    # AWS Access Key ID - 20+ chars: 4-char prefix + 16+ chars (A-Z, 0-9)
    # AKIA (long-term), ASIA (temporary/STS), other prefixes for different resource types
    # Using {16,} to be lenient and catch variations
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16,}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)(aws_?secret_?access_?key|secret_?access_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),

    # GitHub Personal Access Token - 40 chars total: ghp_ (4) + 36 chars, but can be up to 255
    # Modern PATs can be longer, so we use 30+ to catch variations
    "GitHub Personal Access Token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),

    # Slack - various token types with xox prefix
    "Slack Token": re.compile(r"\bxox[bpaeors]-[A-Za-z0-9-]{10,}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),

    # Stripe - sk/rk/pk + live/test + base64-like string (typically 24+ chars after prefix)
    "Stripe Secret Key": re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_(live|test)_[A-Za-z0-9]{20,}\b"),

    # Twilio - 34 chars total (AC/SK + 32 hex chars)
    "Twilio Account SID": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    "Twilio API Key SID": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Twilio Auth Token": re.compile(r"(?i)\b(twilio_)?auth(_)?token['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?"),

    # SendGrid - SG. + base64-like segments
    "SendGrid API Key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{30,}\b"),

    # Discord - 3-part base64-like token with dots
    # First part starts with M, N, or O (base64 encoded snowflake ID)
    "Discord Bot/User Token": re.compile(r"\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b"),
    "Discord Webhook": re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{5,30}/[A-Za-z0-9_-]{30,}"),

    # Telegram - bot ID (7-12 digits) : token (35+ chars to be lenient)
    "Telegram Bot Token": re.compile(r"\b\d{7,12}:[A-Za-z0-9_-]{35,}\b"),

    # Google API Key - exactly 39 chars: AIza + 35 chars (letters, digits, -, _, \)
    # Being slightly lenient (32-40 chars after prefix) to catch variations
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_\\]{32,40}\b"),
    "Google OAuth Token": re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"),
    "GCP Service Account": re.compile(r"\b[A-Za-z0-9\-\_]+@[A-Za-z0-9\-\_]+\.iam\.gserviceaccount\.com\b"),

    # OpenAI - sk- or sk-proj- + alphanumeric (20-200 chars to be safe)
    "OpenAI API Key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{20,200}\b"),

    # GitLab - glpat- + 20+ chars
    "GitLab Personal Access Token": re.compile(r"\bglpat-[0-9A-Za-z\-_]{20,}\b"),

    # Package managers
    "npm Token": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    "PyPI Token": re.compile(r"\bpypi-[A-Za-z0-9\-_]{40,}\b"),

    # Atlassian - Basic Auth with credentials in URL
    "Atlassian API Token (Basic Auth)": re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),

    # Azure
    "Azure Storage Connection String": re.compile(r"DefaultEndpointsProtocol=(?:http|https);AccountName=[A-Za-z0-9\-]+;AccountKey=([A-Za-z0-9+/=]{40,});EndpointSuffix=core\.windows\.net"),
    "Azure SAS Token": re.compile(r"[\?&]sv=\d{4}-\d{2}-\d{2}[^ \n]*?&sig=[A-Za-z0-9%+/=]{16,}"),

    # JWT - 3 base64 segments separated by dots
    "JWT Token": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),

    # Private Keys
    "Private Key (PEM)": re.compile(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "OpenSSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----"),

    # Generic patterns (high false positive risk - keep at end)
    "Password Assignment": re.compile(r"(?i)\b(pass(word)?|pwd)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"),
    "API Key Assignment": re.compile(r"(?i)\b(api[_\-]?key|token|secret|client_secret)\s*[:=]\s*['\"][^'\"\n]{16,}['\"]"),

    # Additional providers
    "Bitbucket App Password": re.compile(r"https://[^/\s:@]+:[^/\s:@]+@bitbucket\.org"),
    "Databricks PAT": re.compile(r"\bdapi[A-Za-z0-9]{32}\b"),
    "Firebase FCM Server Key": re.compile(r"AAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{140,}"),
    "Shopify Token": re.compile(r"\bshp(at|pa|ss)_[0-9a-f]{32}\b"),
    "Notion Integration Token": re.compile(r"\bsecret_[A-Za-z0-9]{32,}\b"),
    "Linear API Key": re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"),
    "Mapbox Access Token": re.compile(r"\b[ps]k\.[A-Za-z0-9\-_.]{30,}\b"),
    "Dropbox Access Token": re.compile(r"\bsl\.[A-Za-z0-9_-]{120,}\b"),
    "DigitalOcean Personal Access Token": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    "Square Access Token": re.compile(r"\bEAAA[A-Za-z0-9]{60}\b"),
    "Airtable Personal Access Token": re.compile(r"\bpat[A-Za-z0-9]{14}\b"),
    "Airtable Legacy API Key": re.compile(r"\bkey[A-Za-z0-9]{14}\b"),
    "Facebook Access Token": re.compile(r"\bEAA[A-Za-z0-9]{30,}\b"),
}

def dedupe_preserve_order(items):
    """Return unique trimmed strings while keeping their original order."""
    seen = set()
    result = []
    for item in items:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(item)
    return result


def _flatten_for_keys(value, allowed_keys):
    """Extract textual values found underneath allowed keys in nested structures."""
    if isinstance(value, str):
        return [value] if value.strip() else []

    collected = []

    def _walk(node, allowed):
        if isinstance(node, str):
            if node.strip() and allowed:
                collected.append(node)
            return
        if isinstance(node, list):
            for item in node:
                _walk(item, allowed)
            return
        if isinstance(node, dict):
            for key, nested in node.items():
                if isinstance(key, str):
                    lower = key.lower()
                    next_allowed = allowed or (lower in allowed_keys)
                else:
                    next_allowed = allowed
                _walk(nested, next_allowed)

    _walk(value, False)
    return collected


def _extract_message_entry(entry):
    """Pull all textual segments from a single message dict (user role only)."""
    if isinstance(entry, str):
        return [entry] if entry.strip() else []
    if not isinstance(entry, dict):
        return []
    if entry.get("role") != "user":
        return []

    collected = []
    content = entry.get("content")

    if isinstance(content, list):
        for piece in content:
            if isinstance(piece, dict):
                p_type = piece.get("type")
                if p_type in {"text", "input_text"} and isinstance(piece.get("text"), str):
                    collected.append(piece["text"])
                else:
                    collected.extend(_flatten_for_keys(piece, USER_MESSAGE_KEYS))
            elif isinstance(piece, str):
                if piece.strip():
                    collected.append(piece)
    elif isinstance(content, str):
        if content.strip():
            collected.append(content)
    elif isinstance(content, dict):
        collected.extend(_flatten_for_keys(content, USER_MESSAGE_KEYS))

    if isinstance(entry.get("text"), str) and entry["text"].strip():
        collected.append(entry["text"])

    return collected


def extract_user_messages(hook_input):
    """Return unique user-authored text snippets from the hook payload."""
    if not isinstance(hook_input, dict):
        return []

    texts = []

    messages = hook_input.get("messages")
    if isinstance(messages, list):
        for entry in messages:
            texts.extend(_extract_message_entry(entry))

    for key in ("message", "input", "input_text", "prompt", "body", "text", "userMessage"):
        if key in hook_input:
            texts.extend(_flatten_for_keys(hook_input[key], USER_MESSAGE_KEYS))

    return dedupe_preserve_order(texts)


def extract_command_outputs(tool_result):
    """Parse tool results and return labelled textual outputs for scanning."""
    outputs = []

    def _walk(node, label=None, allowed=False):
        if isinstance(node, str):
            if node.strip() and (allowed or label is None):
                outputs.append((label or "content", node))
            return
        if isinstance(node, list):
            for item in node:
                _walk(item, label, allowed)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    lower = key.lower()
                    next_allowed = allowed or (lower in COMMAND_OUTPUT_KEYS)
                    next_label = key if lower in COMMAND_OUTPUT_KEYS else label
                else:
                    next_allowed = allowed
                    next_label = label
                _walk(value, next_label, next_allowed)

    if isinstance(tool_result, str):
        if tool_result.strip():
            outputs.append(("content", tool_result))
    else:
        _walk(tool_result, None, False)

    unique = []
    seen = set()
    for label, text in outputs:
        normalized = text.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append((label or "content", text))

    return unique


def detect_tool_name(tool_input):
    """Best-effort extraction of a tool name for labelling."""
    if isinstance(tool_input, str) and tool_input.strip():
        return tool_input

    if isinstance(tool_input, dict):
        for key in ("tool_name", "toolName", "name", "type"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value

        if isinstance(tool_input.get("command"), str):
            return "command"

    return "tool"


def format_output_label(raw_label, tool_name, file_path):
    """Derive a human-friendly label for scanned post-hook payloads."""
    if file_path and isinstance(raw_label, str) and raw_label.lower() in {"content", "text", "message"}:
        return file_path

    base_tool = (tool_name or "tool").strip() or "tool"

    if isinstance(raw_label, str):
        lower = raw_label.lower()
        if lower in {"stdout", "stderr"}:
            return f"[{base_tool} {lower}]"
        if lower in {"content", "text", "message", "result", "output", "body"}:
            return f"[{base_tool} output]"
        return f"[{base_tool} {raw_label}]"

    return f"[{base_tool} output]"


def build_findings_message(findings, heading):
    """Summarise findings grouped by their logical source."""
    if not findings:
        return heading

    grouped = {}
    for item in findings:
        label = item.get("file") or "[unknown]"
        grouped.setdefault(label, []).append(item)

    lines = []
    for label, entries in grouped.items():
        types = sorted({entry["type"] for entry in entries})
        line_numbers = ", ".join(str(entry["line"]) for entry in entries[:SUMMARY_LIMIT])
        detail = f"{label}: {', '.join(types[:3])}"
        if line_numbers:
            detail += f" (lines {line_numbers})"
        if len(entries) > SUMMARY_LIMIT:
            detail += f" (+{len(entries) - SUMMARY_LIMIT} more)"
        lines.append(detail)

    summary = "\n".join(f" - {line}" for line in lines[:SUMMARY_LIMIT])
    message = f"{heading}\n{summary}"

    total_findings = len(findings)
    if total_findings > SUMMARY_LIMIT:
        message += f"\nShowing first {SUMMARY_LIMIT} of {total_findings} findings."

    return message


def collect_post_payloads(hook_input, hook_type, event_name=None):
    """Return labelled payloads that should be scanned after a tool runs."""
    if not isinstance(hook_input, dict):
        return []

    payloads = []
    seen = set()

    if hook_type == "cursor":
        event = (event_name or "").strip()
        tool_name = "shell" if event == "afterShellExecution" else "tool"
        file_path = hook_input.get("file_path", "")

        for raw_label, text in extract_command_outputs(hook_input):
            label = format_output_label(raw_label, tool_name, file_path)
            key = (label, text.strip())
            if not key[1] or key in seen:
                continue
            seen.add(key)
            payloads.append((label, text))

        return payloads

    # Try both tool_input (new format) and toolInput (old format)
    tool_input = hook_input.get("tool_input") or hook_input.get("toolInput")
    if not isinstance(tool_input, dict):
        tool_input = {}

    # Try both tool_response (new format) and toolResult (old format)
    tool_result = hook_input.get("tool_response") or hook_input.get("toolResult")
    file_path = tool_input.get("file_path", "")
    tool_name = hook_input.get("tool_name") or detect_tool_name(tool_input)

    for raw_label, text in extract_command_outputs(tool_result):
        label = format_output_label(raw_label, tool_name, file_path)
        key = (label, text.strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        payloads.append((label, text))

    return payloads

def scan_text(text: str, path: str):
    findings = []
    for pname, rx in PATTERNS.items():
        for m in rx.finditer(text):
            s = m.group(0)
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append({"file": path, "line": line_no, "type": pname, "match": s})
    return findings

def scan_file(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File does not exist: {path}")
    if not should_scan_file(path):
        return []

    file_size = os.path.getsize(path)
    if file_size > MAX_SCAN_BYTES:
        raise RuntimeError(
            f"File size {file_size} bytes exceeds scan limit of {MAX_SCAN_BYTES} bytes"
        )

    try:
        with open(path, "rb") as f:
            blob = f.read()
    except Exception as exc:
        raise RuntimeError(f"Failed to read {path}: {exc}") from exc

    if is_probably_binary(blob):
        return []

    text = blob.decode("utf-8", "ignore")
    return scan_text(text, path)

# ============================================================================
# HOOK INTEGRATION LOGIC
# ============================================================================

def detect_hook_type(hook_input):
    """Detect whether this is Claude Code or Cursor based on input structure."""
    if "hook_event_name" in hook_input:
        return "cursor"
    elif "toolInput" in hook_input or "toolResult" in hook_input:
        return "claude_code"
    else:
        return "claude_code"

def get_file_path_pre(hook_input, hook_type):
    """Extract file path for pre-read hook."""
    if hook_type == "cursor":
        return hook_input.get("file_path", "")
    else:  # claude_code
        # Try both tool_input (new format) and toolInput (old format)
        tool_params = hook_input.get("tool_input") or hook_input.get("toolInput", {})
        return tool_params.get("file_path", "")

def format_output(action, message, hook_type, event_name=None, hook_event="PreToolUse"):
    """Format output based on hook type."""
    cleaned_message = message.rstrip() if isinstance(message, str) else None

    if hook_type == "cursor":
        event = (event_name or "").strip()
        permission_map = {"allow": "allow", "block": "deny", "ask": "ask"}

        if event == "beforeSubmitPrompt":
            payload = {"continue": action != "block"}
            if cleaned_message:
                payload["userMessage"] = cleaned_message
            return payload

        if event in {"beforeReadFile", "beforeShellExecution", "beforeMCPExecution"}:
            payload = {"permission": permission_map.get(action, "allow")}
            if cleaned_message:
                payload["userMessage"] = cleaned_message
            return payload

        if event in {"afterFileEdit", "afterShellExecution", "afterMCPExecution", "stop"}:
            payload = {}
            if cleaned_message:
                payload["message"] = cleaned_message
            return payload

        # Fallback for any other cursor events.
        payload = {}
        if action in permission_map:
            payload["permission"] = permission_map[action]
        elif action == "block":
            payload["permission"] = "deny"

        if cleaned_message:
            payload["userMessage"] = cleaned_message

        if not payload:
            payload["continue"] = action != "block"

        return payload

    # Claude Code format (new format with hookSpecificOutput)
    if hook_event == "PreToolUse":
        # Map old action names to new permission decisions
        permission_decision = "deny" if action == "block" else "allow"
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission_decision
            }
        }
        if cleaned_message:
            result["hookSpecificOutput"]["permissionDecisionReason"] = cleaned_message
        return result
    elif hook_event == "PostToolUse":
        # PostToolUse: use "decision": "block" to alert Claude
        result = {}
        if action == "block" and cleaned_message:
            result["decision"] = "block"
            result["reason"] = cleaned_message
        result["hookSpecificOutput"] = {
            "hookEventName": "PostToolUse"
        }
        if cleaned_message and action != "block":
            result["hookSpecificOutput"]["additionalContext"] = cleaned_message
        return result
    elif hook_event == "UserPromptSubmit":
        # UserPromptSubmit: "decision": "block" prevents prompt from being processed
        result = {}
        if action == "block":
            result["decision"] = "block"
            if cleaned_message:
                result["reason"] = cleaned_message
        result["hookSpecificOutput"] = {
            "hookEventName": "UserPromptSubmit"
        }
        if cleaned_message and action != "block":
            result["hookSpecificOutput"]["additionalContext"] = cleaned_message
        return result
    else:
        # Fallback for other hooks
        result = {"action": action}
        if cleaned_message:
            result["message"] = cleaned_message
        return result

def run_pre_hook(client_override=None):
    """Run pre-read hook - scan file paths and user submissions."""
    hook_type = "claude_code"
    event_name = None

    try:
        hook_input = json.load(sys.stdin)

        # Use explicit client type if provided, otherwise auto-detect
        if client_override:
            hook_type = client_override
        else:
            hook_type = detect_hook_type(hook_input)

        # Get the hook event name from input
        event_name = hook_input.get("hook_event_name")

        # For Claude Code, use the hook_event_name directly
        if hook_type == "claude_code":
            hook_event = event_name or "PreToolUse"  # Default to PreToolUse if not specified
        else:
            hook_event = "PreToolUse"  # Default for Cursor

        findings = []

        file_path = get_file_path_pre(hook_input, hook_type)
        inline_content = hook_input.get("content") if hook_type == "cursor" else None

        if isinstance(inline_content, str) and inline_content.strip():
            label = file_path or "[file content]"
            findings.extend(scan_text(inline_content, label))
        elif file_path:
            try:
                findings.extend(scan_file(file_path))
            except Exception as exc:
                message = f"⚠️  Secret scan error: {exc}"
                output = json.dumps(format_output("block", message, hook_type, event_name, hook_event))
                if hook_type == "claude_code":
                    sys.stderr.write(output + "\n")
                    sys.stderr.flush()
                    sys.exit(2)
                else:
                    print(output)
                return

        for idx, message_text in enumerate(extract_user_messages(hook_input), start=1):
            label = f"[user message #{idx}]"
            findings.extend(scan_text(message_text, label))

        if findings:
            message = build_findings_message(findings, "⚠️ SECRET DETECTED (submission blocked)")
            output = json.dumps(format_output("block", message, hook_type, event_name, hook_event))
            if hook_type == "claude_code":
                sys.stderr.write(output + "\n")
                sys.stderr.flush()
                sys.exit(2)
            else:
                print(output)
        else:
            output = json.dumps(format_output("allow", None, hook_type, event_name, hook_event))
            if hook_type == "claude_code":
                sys.stdout.write(output + "\n")
                sys.stdout.flush()
                sys.exit(0)
            else:
                print(output)

    except Exception as exc:
        message = f"⚠️  Secret scan error: {exc}"
        output = json.dumps(format_output("block", message, hook_type, event_name, "UserPromptSubmit"))
        if hook_type == "claude_code":
            sys.stderr.write(output + "\n")
            sys.stderr.flush()
            sys.exit(2)
        else:
            print(output)

def run_post_hook(client_override=None):
    """Run post-read hook - scan tool output (file reads, command stdout, etc.)."""
    hook_type = "claude_code"
    event_name = None

    try:
        hook_input = json.load(sys.stdin)

        # Use explicit client type if provided, otherwise auto-detect
        if client_override:
            hook_type = client_override
        else:
            hook_type = detect_hook_type(hook_input)

        event_name = hook_input.get("hook_event_name") if hook_type == "cursor" else None

        payloads = collect_post_payloads(hook_input, hook_type, event_name)
        if not payloads:
            output = json.dumps(format_output("allow", None, hook_type, event_name, "PostToolUse"))
            if hook_type == "claude_code":
                sys.stdout.write(output + "\n")
                sys.stdout.flush()
                sys.exit(0)
            else:
                print(output)
            return

        findings = []
        for label, text in payloads:
            findings.extend(scan_text(text, label))

        if findings:
            heading = "🚨 SECRET DETECTED in recent output"
            message = build_findings_message(findings, heading)
            message += "\n⚠️  Be careful with this sensitive data!"
            output = json.dumps(format_output("block", message, hook_type, event_name, "PostToolUse"))
            if hook_type == "claude_code":
                sys.stderr.write(output + "\n")
                sys.stderr.flush()
                sys.exit(2)
            else:
                print(output)
        else:
            output = json.dumps(format_output("allow", None, hook_type, event_name, "PostToolUse"))
            if hook_type == "claude_code":
                sys.stdout.write(output + "\n")
                sys.stdout.flush()
                sys.exit(0)
            else:
                print(output)

    except Exception as exc:
        fallback_type = hook_type or "claude_code"
        message = f"⚠️  Post-read secret scan error: {exc}"
        output = json.dumps(format_output("allow", message, fallback_type, event_name, "PostToolUse"))
        if hook_type == "claude_code":
            sys.stderr.write(output + "\n")
            sys.stderr.flush()
            sys.exit(1)
        else:
            print(output)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Read hook for secret scanning')
    parser.add_argument('--mode', choices=['pre', 'post'], required=True,
                        help='Hook mode: pre (before read) or post (after read)')
    parser.add_argument('--client', choices=['claude_code', 'cursor'], default=None,
                        help='Client type: claude_code or cursor (auto-detect if not specified)')
    args = parser.parse_args()

    if args.mode == 'pre':
        run_pre_hook(args.client)
    elif args.mode == 'post':
        run_post_hook(args.client)

if __name__ == "__main__":
    main()
