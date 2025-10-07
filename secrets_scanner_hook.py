#!/usr/bin/env python3
"""Secret scanner for Claude Code and Cursor hooks (single-file).

Provides pre/post hook scanning with minimal dependencies. Designed to be
portable (copy one file) while readable and maintainable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from bisect import bisect_right

__all__ = [
    "__version__",
    "main",
    "console_main",
    "console_main_claude",
    "console_main_cursor",
]

__version__ = "0.1.3"

# -----------------------------------------------------------------------------
# Configuration and Patterns
# -----------------------------------------------------------------------------

MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5MB cap per file
SAMPLE_BYTES = 4096  # used for binary sniffing

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


PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16,}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)(aws_?secret_?access_?key|secret_?access_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "GitHub Personal Access Token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    "Slack Token": re.compile(r"\bxox[bpaeors]-[A-Za-z0-9-]{10,}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),
    "Stripe Secret Key": re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_(live|test)_[A-Za-z0-9]{20,}\b"),
    "Twilio Account SID": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    "Twilio API Key SID": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Twilio Auth Token": re.compile(r"(?i)\b(twilio_)?auth(_)?token['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?"),
    "SendGrid API Key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{30,}\b"),
    "Discord Bot/User Token": re.compile(r"\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b"),
    "Discord Webhook": re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{5,30}/[A-Za-z0-9_-]{30,}"),
    "Telegram Bot Token": re.compile(r"\b\d{7,12}:[A-Za-z0-9_-]{35,}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_\\]{32,40}\b"),
    "Google OAuth Token": re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"),
    "GCP Service Account": re.compile(r"\b[A-Za-z0-9\-\_]+@[A-Za-z0-9\-\_]+\.iam\.gserviceaccount\.com\b"),
    "OpenAI API Key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{20,200}\b"),
    "GitLab Personal Access Token": re.compile(r"\bglpat-[0-9A-Za-z\-_]{20,}\b"),
    "npm Token": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    "PyPI Token": re.compile(r"\bpypi-[A-Za-z0-9\-_]{40,}\b"),
    "Atlassian API Token (Basic Auth)": re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    "Azure Storage Connection String": re.compile(r"DefaultEndpointsProtocol=(?:http|https);AccountName=[A-Za-z0-9\-]+;AccountKey=([A-Za-z0-9+/=]{40,});EndpointSuffix=core\.windows\.net"),
    "Azure SAS Token": re.compile(r"[\?&]sv=\d{4}-\d{2}-\d{2}[^ \n]*?&sig=[A-Za-z0-9%+/=]{16,}"),
    "JWT Token": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    "Private Key (PEM)": re.compile(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "OpenSSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----"),
    "Password Assignment": re.compile(r"(?i)\b(pass(word)?|pwd)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"),
    "API Key Assignment": re.compile(r"(?i)\b(api[_\-]?key|token|secret|client_secret)\s*[:=]\s*['\"][^'\"\n]{16,}['\"]"),
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

# -----------------------------------------------------------------------------
# Scanning utilities
# -----------------------------------------------------------------------------

def is_probably_binary(block: bytes) -> bool:
    if b"\x00" in block:
        return True
    textchars = bytes(range(32, 127)) + b"\n\r\t\b"
    nontext = block.translate(None, textchars)
    return len(nontext) / max(1, len(block)) > 0.30


def should_scan_file(path: str) -> bool:
    try:
        with open(path, "rb") as sample:
            head = sample.read(SAMPLE_BYTES)
    except OSError:
        return False
    if not head:
        return True
    return not is_probably_binary(head)


def _iter_texts_for_keys(value, allowed_keys, allowed=False):
    if isinstance(value, str):
        if value.strip() and allowed:
            yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_texts_for_keys(item, allowed_keys, allowed)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            nxt_allowed = allowed or (isinstance(k, str) and k.lower() in allowed_keys)
            yield from _iter_texts_for_keys(v, allowed_keys, nxt_allowed)


def iter_user_texts(payload):
    if not isinstance(payload, dict):
        return
    msgs = payload.get("messages")
    if isinstance(msgs, list):
        for entry in msgs:
            if isinstance(entry, dict) and entry.get("role") == "user":
                content = entry.get("content")
                if isinstance(content, str) and content.strip():
                    yield content
                else:
                    yield from _iter_texts_for_keys(content, USER_MESSAGE_KEYS, True)
                t = entry.get("text")
                if isinstance(t, str) and t.strip():
                    yield t
    for key in ("message", "input", "input_text", "prompt", "body", "text", "userMessage"):
        if key in payload:
            yield from _iter_texts_for_keys(payload[key], USER_MESSAGE_KEYS, True)


def extract_command_outputs(data):
    out = []

    def walk(node, label=None, allowed=False):
        if isinstance(node, str):
            if node.strip() and (allowed or label is None):
                out.append((label or "content", node))
            return
        if isinstance(node, list):
            for it in node:
                walk(it, label, allowed)
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str):
                    lower = k.lower()
                    nxt_allowed = allowed or (lower in COMMAND_OUTPUT_KEYS)
                    nxt_label = k if lower in COMMAND_OUTPUT_KEYS else label
                else:
                    nxt_allowed = allowed
                    nxt_label = label
                walk(v, nxt_label, nxt_allowed)

    if isinstance(data, str):
        if data.strip():
            out.append(("content", data))
    else:
        walk(data)

    seen = set()
    uniq = []
    for label, text in out:
        t = text.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        uniq.append((label or "content", text))
    return uniq


def scan_text(text: str, path: str):
    findings = []
    line_starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(idx + 1)
    for pname, rx in PATTERNS.items():
        for m in rx.finditer(text):
            line_no = bisect_right(line_starts, m.start())
            findings.append({"file": path, "line": line_no, "type": pname, "match": m.group(0)})
    return findings


def scan_file(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File does not exist: {path}")
    if not should_scan_file(path):
        return []
    size = os.path.getsize(path)
    if size > MAX_SCAN_BYTES:
        raise RuntimeError(f"File size {size} bytes exceeds scan limit of {MAX_SCAN_BYTES} bytes")
    with open(path, "rb") as f:
        blob = f.read()
    if is_probably_binary(blob):
        return []
    return scan_text(blob.decode("utf-8", "ignore"), path)


def build_findings_message(findings, heading: str, limit: int = 5) -> str:
    if not findings:
        return heading
    grouped = {}
    for it in findings:
        grouped.setdefault(it.get("file") or "[unknown]", []).append(it)
    lines = []
    for label, entries in grouped.items():
        types = sorted({e["type"] for e in entries})
        nums = ", ".join(str(e["line"]) for e in entries[:limit])
        s = f"{label}: {', '.join(types[:3])}"
        if nums:
            s += f" (lines {nums})"
        if len(entries) > limit:
            s += f" (+{len(entries) - limit} more)"
        lines.append(s)
    msg = "\n".join(f" - {ln}" for ln in lines[:limit])
    out = f"{heading}\n{msg}"
    total = len(findings)
    if total > limit:
        out += f"\nShowing first {limit} of {total} findings."
    return out


# -----------------------------------------------------------------------------
# Client adapters (Cursor / Claude)
# -----------------------------------------------------------------------------

def detect_hook_type(hook_input):
    if isinstance(hook_input, dict) and "hook_event_name" in hook_input:
        return "cursor"
    return "claude_code"


def get_file_path_pre(hook_input, hook_type: str):
    if hook_type == "cursor":
        return hook_input.get("file_path", "")
    tool_params = hook_input.get("tool_input") or hook_input.get("toolInput", {})
    return tool_params.get("file_path", "") if isinstance(tool_params, dict) else ""


def _label_for_output(raw_label: str, tool_name: str, file_path: str) -> str:
    if file_path and isinstance(raw_label, str) and raw_label.lower() in {"content", "text", "message"}:
        return file_path
    base = (tool_name or "tool").strip() or "tool"
    if isinstance(raw_label, str):
        lower = raw_label.lower()
        if lower in {"stdout", "stderr"}:
            return f"[{base} {lower}]"
        if lower in {"content", "text", "message", "result", "output", "body"}:
            return f"[{base} output]"
        return f"[{base} {raw_label}]"
    return f"[{base} output]"


def _detect_tool_name(tool_input) -> str:
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


def collect_cursor_post_payloads(hook_input, event_name: str | None):
    tool_name = "shell" if (event_name or "") == "afterShellExecution" else "tool"
    file_path = hook_input.get("file_path", "")
    seen = set()
    payloads = []
    for raw_label, text in extract_command_outputs(hook_input):
        label = _label_for_output(raw_label, tool_name, file_path)
        key = (label, text.strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        payloads.append((label, text))
    return payloads


def collect_claude_post_payloads(hook_input):
    tool_input = hook_input.get("tool_input") or hook_input.get("toolInput") or {}
    tool_result = hook_input.get("tool_response") or hook_input.get("toolResult")
    file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""
    tool_name = hook_input.get("tool_name") or _detect_tool_name(tool_input)
    seen = set()
    payloads = []
    for raw_label, text in extract_command_outputs(tool_result):
        label = _label_for_output(raw_label, tool_name, file_path)
        key = (label, text.strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        payloads.append((label, text))
    return payloads


def format_cursor_response(action: str, message: str | None, event_name: str | None):
    permission_map = {"allow": "allow", "block": "deny", "ask": "ask"}
    event = (event_name or "").strip()
    if event == "beforeSubmitPrompt":
        payload = {"continue": action != "block"}
        if message:
            payload["userMessage"] = message
        return payload
    if event in {"beforeReadFile", "beforeShellExecution", "beforeMCPExecution"}:
        payload = {"permission": permission_map.get(action, "allow")}
        if message:
            payload["userMessage"] = message
        return payload
    if event in {"afterFileEdit", "afterShellExecution", "afterMCPExecution", "stop"}:
        payload = {}
        if message:
            payload["message"] = message
        return payload
    payload = {}
    if action in permission_map:
        payload["permission"] = permission_map[action]
    elif action == "block":
        payload["permission"] = "deny"
    if message:
        payload["userMessage"] = message
    if not payload:
        payload["continue"] = action != "block"
    return payload


def format_claude_response(action: str, message: str | None, hook_event: str):
    msg = message.rstrip() if isinstance(message, str) else None
    if hook_event == "PreToolUse":
        decision = "deny" if action == "block" else "allow"
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}}
        if msg:
            out["hookSpecificOutput"]["permissionDecisionReason"] = msg
        return out
    if hook_event == "PostToolUse":
        out = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
        if action == "block" and msg:
            out["decision"] = "block"
            out["reason"] = msg
        elif msg:
            out["hookSpecificOutput"]["additionalContext"] = msg
        return out
    if hook_event == "UserPromptSubmit":
        out = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
        if action == "block":
            out["decision"] = "block"
            if msg:
                out["reason"] = msg
        elif msg:
            out["hookSpecificOutput"]["additionalContext"] = msg
        return out
    out = {"action": action}
    if msg:
        out["message"] = msg
    return out


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def _emit(hook_type: str, hook_event: str, action: str, message: str | None, event_name: str | None = None, *, allow_code=0, block_code=2, warn_code=1):
    if hook_type == "cursor":
        print(json.dumps(format_cursor_response(action, message, event_name)))
        return
    payload = format_claude_response(action, message, hook_event)
    text = json.dumps(payload)
    if action == "block":
        sys.stderr.write(text + "\n")
        sys.stderr.flush()
        sys.exit(block_code)
    else:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        sys.exit(allow_code)


def run_pre_hook(client_override: str | None = None):
    hook_type = "claude_code"
    event_name = None
    try:
        hook_input = json.load(sys.stdin)
        hook_type = client_override or detect_hook_type(hook_input)
        event_name = hook_input.get("hook_event_name")
        hook_event = event_name or ("PreToolUse" if hook_type == "claude_code" else "beforeReadFile")

        findings = []
        file_path = get_file_path_pre(hook_input, hook_type)
        inline_content = hook_input.get("content") if hook_type == "cursor" else None
        if isinstance(inline_content, str) and inline_content.strip():
            findings.extend(scan_text(inline_content, file_path or "[file content]"))
        elif file_path:
            try:
                findings.extend(scan_file(file_path))
            except Exception as exc:
                _emit(hook_type, hook_event, "block", f"Secret scan error: {exc}", event_name)
                return
        for idx, msg in enumerate(iter_user_texts(hook_input), start=1):
            findings.extend(scan_text(msg, f"[user message #{idx}]"))
        if findings:
            _emit(hook_type, hook_event, "block", build_findings_message(findings, "SECRET DETECTED (submission blocked)"), event_name)
        else:
            _emit(hook_type, hook_event, "allow", None, event_name)
    except Exception as exc:
        _emit(hook_type, "UserPromptSubmit", "block", f"Secret scan error: {exc}", event_name)


def run_post_hook(client_override: str | None = None):
    hook_type = "claude_code"
    event_name = None
    try:
        hook_input = json.load(sys.stdin)
        hook_type = client_override or detect_hook_type(hook_input)
        event_name = hook_input.get("hook_event_name") if hook_type == "cursor" else None
        payloads = collect_cursor_post_payloads(hook_input, event_name) if hook_type == "cursor" else collect_claude_post_payloads(hook_input)
        if not payloads:
            _emit(hook_type, "PostToolUse", "allow", None, event_name)
            return
        findings = []
        for label, text in payloads:
            findings.extend(scan_text(text, label))
        if findings:
            msg = build_findings_message(findings, "SECRET DETECTED in recent output") + "\nBe careful with this sensitive data!"
            _emit(hook_type, "PostToolUse", "block", msg, event_name)
        else:
            _emit(hook_type, "PostToolUse", "allow", None, event_name)
    except Exception as exc:
        if hook_type == "claude_code":
            sys.stderr.write(json.dumps(format_claude_response("allow", f"Post-read secret scan error: {exc}", "PostToolUse")) + "\n")
            sys.stderr.flush()
            sys.exit(1)
        else:
            print(json.dumps(format_cursor_response("allow", f"Post-read secret scan error: {exc}", event_name)))


def _build_cli_parser():
    p = argparse.ArgumentParser(description=f"Secret scanner hooks v{__version__}")
    p.add_argument("--mode", choices=["pre", "post"], required=True)
    p.add_argument("--client", choices=["claude_code", "cursor"], default=None)
    return p


def main(argv=None, *, default_client=None):
    args = _build_cli_parser().parse_args(argv) if argv is not None else _build_cli_parser().parse_args()
    if default_client and args.client is None:
        args.client = default_client
    if args.mode == "pre":
        run_pre_hook(args.client)
    else:
        run_post_hook(args.client)


def console_main():
    main()


def console_main_claude():
    main(default_client="claude_code")


def console_main_cursor():
    main(default_client="cursor")


if __name__ == "__main__":
    main()
