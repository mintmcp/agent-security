from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Tuple

from . import __version__
from .clients import (
    collect_claude_post_payloads,
    collect_cursor_post_payloads,
    detect_hook_type,
    format_claude_response,
    format_cursor_response,
    get_file_path_pre,
)
from .core import (
    build_findings_message,
    iter_user_texts,
    scan_file,
    scan_text,
)


def _emit(hook_type: str, hook_event: str, action: str, message: str | None, event_name: str | None = None, *, allow_code=0, block_code=2, warn_code=1):
    if hook_type == "cursor":
        payload = format_cursor_response(action, message, event_name)
        print(json.dumps(payload))
        return

    # Claude Code
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

        findings: List[Dict] = []
        file_path = get_file_path_pre(hook_input, hook_type)
        inline_content = hook_input.get("content") if hook_type == "cursor" else None

        if isinstance(inline_content, str) and inline_content.strip():
            label = file_path or "[file content]"
            findings.extend(scan_text(inline_content, label))
        elif file_path:
            try:
                findings.extend(scan_file(file_path))
            except Exception as exc:
                _emit(hook_type, hook_event, "block", f"Secret scan error: {exc}", event_name)
                return

        # user messages
        for idx, msg in enumerate(iter_user_texts(hook_input), start=1):
            findings.extend(scan_text(msg, f"[user message #{idx}]"))

        if findings:
            heading = "SECRET DETECTED (submission blocked)"
            message = build_findings_message(findings, heading)
            _emit(hook_type, hook_event, "block", message, event_name)
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

        if hook_type == "cursor":
            payloads = collect_cursor_post_payloads(hook_input, event_name)
        else:
            payloads = collect_claude_post_payloads(hook_input)

        if not payloads:
            _emit(hook_type, "PostToolUse", "allow", None, event_name)
            return

        findings: List[Dict] = []
        for label, text in payloads:
            findings.extend(scan_text(text, label))

        if findings:
            heading = "SECRET DETECTED in recent output"
            message = build_findings_message(findings, heading)
            message += "\nBe careful with this sensitive data!"
            _emit(hook_type, "PostToolUse", "block", message, event_name)
        else:
            _emit(hook_type, "PostToolUse", "allow", None, event_name)

    except Exception as exc:
        # Non-blocking error for post hook
        payload = format_cursor_response("allow", f"Post-read secret scan error: {exc}", event_name) if hook_type == "cursor" else format_claude_response("allow", f"Post-read secret scan error: {exc}", "PostToolUse")
        text = json.dumps(payload)
        if hook_type == "claude_code":
            sys.stderr.write(text + "\n")
            sys.stderr.flush()
            sys.exit(1)
        else:
            print(text)


def _build_cli_parser():
    parser = argparse.ArgumentParser(description=f"Secret scanner hooks v{__version__}")
    parser.add_argument("--mode", choices=["pre", "post"], required=True)
    parser.add_argument("--client", choices=["claude_code", "cursor"], default=None)
    return parser


def main(argv=None, *, default_client=None):
    parser = _build_cli_parser()
    args = parser.parse_args(argv) if argv is not None else parser.parse_args()
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

