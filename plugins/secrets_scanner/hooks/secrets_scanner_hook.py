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

__version__ = "0.1.7"

# -----------------------------------------------------------------------------
# Configuration and Patterns
# -----------------------------------------------------------------------------

MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5MB cap per file
SAMPLE_BYTES = 4096  # used for binary sniffing


# (strict schema access; direct .get only)


PATTERNS = {
    # AWS
    "AWS Access Key ID": re.compile(r"\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[A-Z0-9]{16}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)(?:aws_?secret_?access_?key|secret_?access_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),

    # GitHub / GitLab
    "GitHub Token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    "GitLab Tokens": re.compile(r"\b(?:glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50}(?!\w)\b|\bGR1348941[A-Za-z0-9_\-]{20,50}(?!\w)\b|\bglcbt-(?:[0-9a-fA-F]{2}_)?[A-Za-z0-9_\-]{20,50}(?!\w)\b|\bglimt-[A-Za-z0-9_\-]{25}(?!\w)\b|\bglptt-[A-Za-z0-9_\-]{40}(?!\w)\b|\bglagent-[A-Za-z0-9_\-]{50,1024}(?!\w)\b|\bgloas-[A-Za-z0-9_\-]{64}(?!\w)\b"),

    # Slack / Discord / Telegram
    "Slack Token": re.compile(r"xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+", re.IGNORECASE),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", re.IGNORECASE),
    "Discord Bot Token": re.compile(r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b"),
    "Discord Webhook": re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{5,30}/[A-Za-z0-9_-]{30,}"),
    "Telegram Bot Token": re.compile(r"\b\d{8,10}:[0-9A-Za-z_-]{35}\b"),

    # Stripe / Twilio / SendGrid
    "Stripe Secret Key": re.compile(r"\b(?:r|s)k_(?:live|test)_[0-9A-Za-z]{24,}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    "Twilio Account SID": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    "Twilio API Key SID": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Twilio Auth Token": re.compile(r"(?i)\b(?:twilio_)?auth_?token['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?"),
    "SendGrid API Key": re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),

    # Package registries
    "NPM Token": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    "NPM .npmrc Auth Token": re.compile(r"\/\/[^\n]+\/:_authToken=\s*((npm_.+)|([A-Fa-f0-9-]{36}))"),
    "PyPI Token": re.compile(r"\bpypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9-_]{70,}\b"),

    # Cloud providers & services
    "Azure Storage Connection String": re.compile(r"DefaultEndpointsProtocol=(?:http|https);AccountName=[A-Za-z0-9\-]+;AccountKey=([A-Za-z0-9+/=]{40,});EndpointSuffix=core\.windows\.net"),
    "Azure Storage Account Key": re.compile(r"AccountKey=[A-Za-z0-9+/=]{88}"),
    "Azure SAS Token": re.compile(r"[\?&]sv=\d{4}-\d{2}-\d{2}[^ \n]*?&sig=[A-Za-z0-9%+/=]{16,}"),
    "Artifactory Credentials": re.compile(r"(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}(?:\s|\"|$)"),
    "Artifactory Encrypted Password": re.compile(r"(?:\s|=|:|\"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|\"|$)"),
    "Cloudant URL Credential": re.compile(r"https?://[\w\-]+:([0-9a-f]{64}|[a-z]{24})@[\w\-]+\.cloudant\.com", re.IGNORECASE),
    "SoftLayer API Token": re.compile(r"https?://api\.softlayer\.com/soap/(?:v3|v3\.1)/([a-z0-9]{64})", re.IGNORECASE),

    # JWT and keys
    "JWT Token": re.compile(r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*?\b"),
    "Private Key (PEM)": re.compile(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----\s*\n(?:(?:[A-Za-z0-9\-]+:[^\n]*\n)*\s*)?(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "OpenSSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----\s*\n(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END OPENSSH PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----\s*\n(?:(?:[A-Za-z0-9\-]+:[^\n]*\n)*\s*)?(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END PGP PRIVATE KEY BLOCK-----"),
    "SSH2 Encrypted Private Key": re.compile(r"-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----\s*\n(?:[A-Za-z0-9+/=]{40,}\s*\n)+-----END SSH2 ENCRYPTED PRIVATE KEY-----"),
    "PuTTY Private Key": re.compile(r"(?:^|\n)PuTTY-User-Key-File-\d+:\s*\S+"),

    # Other common tokens
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_\\]{32,40}\b"),
    "Google OAuth Token": re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"),
    "OpenAI API Key": re.compile(r"\bsk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    "Password Assignment": re.compile(r"(?i)\b(pass(word)?|pwd)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"),
    "Mailchimp API Key": re.compile(r"\b[0-9a-z]{32}-us[0-9]{1,2}\b"),
    # From detect-secrets basic_auth plugin, limits username/password chars to avoid false positives
    "Basic Auth Credentials": re.compile(r"://[^:/?#\[\]@!$&'()*+,;=\s]+:([^:/?#\[\]@!$&'()*+,;=\s]+)@"),
    "Databricks PAT": re.compile(r"\bdapi[A-Za-z0-9]{32}\b"),
    "Firebase FCM Server Key": re.compile(r"\bAAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{140,}\b"),
    "Shopify Token": re.compile(r"\bshp(?:at|pa|ss)_[0-9a-f]{32}\b"),
    "Notion Integration Token": re.compile(r"\bsecret_[A-Za-z0-9]{32,}\b"),
    "Linear API Key": re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"),
    "Mapbox Access Token": re.compile(r"\b[ps]k\.[A-Za-z0-9\-_.]{30,}\b"),
    "Dropbox Access Token": re.compile(r"\bsl\.[A-Za-z0-9_-]{120,}\b"),
    "DigitalOcean Personal Access Token": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    "Square Access Token": re.compile(r"\bEAAA[A-Za-z0-9]{60}\b"),
    "Square OAuth Secret": re.compile(r"\bsq0csp-[0-9A-Za-z_\-]{43}\b"),
    "Airtable Personal Access Token": re.compile(r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"),
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
    if not isinstance(hook_input, dict):
        return "claude_code"
    ev = hook_input.get("hook_event_name")
    if isinstance(ev, str):
        ev = ev.strip()
        claude_events = {
            "PreToolUse",
            "PostToolUse",
            "UserPromptSubmit",
            "Notification",
            "Stop",
            "SubagentStop",
            "PreCompact",
            "SessionStart",
            "SessionEnd",
        }
        cursor_events = {
            "beforeReadFile",
            "afterFileEdit",
            "beforeSubmitPrompt",
            "beforeShellExecution",
            "afterShellExecution",
            "beforeMCPExecution",
            "afterMCPExecution",
            "stop",
        }
        if ev in claude_events:
            return "claude_code"
        if ev in cursor_events:
            return "cursor"
    return "claude_code"


# Removed legacy helpers; using direct documented fields only


def _detect_tool_name(tool_input) -> str:
    if isinstance(tool_input, str) and tool_input.strip():
        return tool_input
    if isinstance(tool_input, dict):
        value = tool_input.get("tool_name")
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(tool_input.get("command"), str):
            return "command"
    return "tool"


def collect_cursor_post_payloads(hook_input, event_name: str | None):
    """Extract Cursor post-event outputs from documented fields."""
    evt = (event_name or "").strip()
    payloads = []

    if evt == "afterShellExecution":
        stdout = hook_input.get("stdout")
        stderr = hook_input.get("stderr")
        if isinstance(stdout, str) and stdout.strip():
            payloads.append(("[shell stdout]", stdout))
        if isinstance(stderr, str) and stderr.strip():
            payloads.append(("[shell stderr]", stderr))
        return payloads

    if evt == "afterMCPExecution":
        for key, label in (
            ("stdout", "[mcp stdout]"),
            ("stderr", "[mcp stderr]"),
            ("text", "[mcp output]"),
            ("message", "[mcp output]"),
        ):
            val = hook_input.get(key)
            if isinstance(val, str) and val.strip():
                payloads.append((label, val))
        return payloads

    return payloads


def collect_claude_post_payloads(hook_input):
    """Extract Claude post-event outputs from documented fields."""
    tool_input = hook_input.get("tool_input") or {}
    tool_result = hook_input.get("tool_response") or {}
    tool_name = (hook_input.get("tool_name") or _detect_tool_name(tool_input) or "").strip()

    payloads = []

    if tool_name.lower() == "bash":
        stdout = tool_result.get("stdout") if isinstance(tool_result, dict) else None
        stderr = tool_result.get("stderr") if isinstance(tool_result, dict) else None
        if isinstance(stdout, str) and stdout.strip():
            payloads.append(("[bash stdout]", stdout))
        if isinstance(stderr, str) and stderr.strip():
            payloads.append(("[bash stderr]", stderr))
        return payloads

    # Read tool or similar may return content directly
    if isinstance(tool_result, dict):
        content = tool_result.get("content")
        if isinstance(content, str) and content.strip():
            label = tool_input.get("file_path") if isinstance(tool_input, dict) else None
            payloads.append((label or "[tool output]", content))
    elif isinstance(tool_result, str) and tool_result.strip():
        label = tool_input.get("file_path") if isinstance(tool_input, dict) else None
        payloads.append((label or "[tool output]", tool_result))

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

        if hook_type == "cursor":
            # Cursor: extract directly per docs, avoid walking arbitrary JSON
            evt = (event_name or "").strip()
            if evt == "beforeReadFile":
                file_path = hook_input.get("file_path") or ""
                content = hook_input.get("content")
                if isinstance(content, str) and content.strip():
                    findings.extend(scan_text(content, file_path or "[file content]"))
                elif file_path:
                    try:
                        findings.extend(scan_file(file_path))
                    except Exception as exc:
                        _emit(hook_type, hook_event, "block", f"Secret scan error: {exc}", event_name)
                        return
            elif evt == "beforeSubmitPrompt":
                prompt = hook_input.get("prompt")
                if isinstance(prompt, str) and prompt.strip():
                    findings.extend(scan_text(prompt, "[prompt]"))
            elif evt == "beforeShellExecution":
                cmd = hook_input.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    findings.extend(scan_text(cmd, "[shell command]"))
            elif evt == "beforeMCPExecution":
                cmd = hook_input.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    findings.extend(scan_text(cmd, "[mcp command]"))
            # No other Cursor pre-events are scanned
        else:
            ev = hook_input.get("hook_event_name") or ""
            ev = ev.strip()

            if ev == "PreToolUse":
                tool_input = hook_input.get("tool_input") or {}
                tool_name = (hook_input.get("tool_name") or _detect_tool_name(tool_input) or "").strip()
                if isinstance(tool_input, dict):
                    if tool_name in {"Write", "Edit", "MultiEdit", "Read"}:
                        content = tool_input.get("content")
                        if isinstance(content, str) and content.strip():
                            findings.extend(scan_text(content, tool_input.get("file_path") or "[content]"))
                        else:
                            fp = tool_input.get("file_path")
                            if isinstance(fp, str) and fp.strip():
                                try:
                                    findings.extend(scan_file(fp))
                                except Exception as exc:
                                    _emit(hook_type, hook_event, "block", f"Secret scan error: {exc}", event_name)
                                    return
                    elif tool_name == "Bash":
                        cmd = tool_input.get("command")
                        if isinstance(cmd, str) and cmd.strip():
                            findings.extend(scan_text(cmd, "[bash command]"))
                    else:
                        content = tool_input.get("content")
                        if isinstance(content, str) and content.strip():
                            findings.extend(scan_text(content, "[tool content]"))

            elif ev == "UserPromptSubmit":
                prompt = hook_input.get("prompt")
                if isinstance(prompt, str) and prompt.strip():
                    findings.extend(scan_text(prompt, "[prompt]"))
            # No other Claude pre-events are scanned

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
