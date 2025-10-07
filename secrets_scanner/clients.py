from __future__ import annotations

import json
from typing import Dict, Iterable, List, Tuple

from .core import extract_command_outputs


def detect_hook_type(hook_input: Dict) -> str:
    if isinstance(hook_input, dict) and "hook_event_name" in hook_input:
        return "cursor"
    return "claude_code"


def get_file_path_pre(hook_input: Dict, hook_type: str) -> str:
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


def collect_cursor_post_payloads(hook_input: Dict, event_name: str | None) -> List[Tuple[str, str]]:
    tool_name = "shell" if (event_name or "") == "afterShellExecution" else "tool"
    file_path = hook_input.get("file_path", "")
    seen = set()
    payloads: List[Tuple[str, str]] = []
    for raw_label, text in extract_command_outputs(hook_input):
        label = _label_for_output(raw_label, tool_name, file_path)
        key = (label, text.strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        payloads.append((label, text))
    return payloads


def collect_claude_post_payloads(hook_input: Dict) -> List[Tuple[str, str]]:
    tool_input = hook_input.get("tool_input") or hook_input.get("toolInput") or {}
    tool_result = hook_input.get("tool_response") or hook_input.get("toolResult")
    file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""
    tool_name = hook_input.get("tool_name") or _detect_tool_name(tool_input)

    seen = set()
    payloads: List[Tuple[str, str]] = []
    for raw_label, text in extract_command_outputs(tool_result):
        label = _label_for_output(raw_label, tool_name, file_path)
        key = (label, text.strip())
        if not key[1] or key in seen:
            continue
        seen.add(key)
        payloads.append((label, text))
    return payloads


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


def format_cursor_response(action: str, message: str | None, event_name: str | None) -> Dict:
    """Return JSON payload per Cursor docs."""
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

    # Fallback
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


def format_claude_response(action: str, message: str | None, hook_event: str) -> Dict:
    """Return JSON payload per Claude Code docs."""
    msg = message.rstrip() if isinstance(message, str) else None

    if hook_event == "PreToolUse":
        decision = "deny" if action == "block" else "allow"
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
            }
        }
        if msg:
            out["hookSpecificOutput"]["permissionDecisionReason"] = msg
        return out

    if hook_event == "PostToolUse":
        out: Dict = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
        if action == "block" and msg:
            out["decision"] = "block"
            out["reason"] = msg
        elif msg:
            out["hookSpecificOutput"]["additionalContext"] = msg
        return out

    if hook_event == "UserPromptSubmit":
        out: Dict = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
        if action == "block":
            out["decision"] = "block"
            if msg:
                out["reason"] = msg
        elif msg:
            out["hookSpecificOutput"]["additionalContext"] = msg
        return out

    # Fallback
    out = {"action": action}
    if msg:
        out["message"] = msg
    return out

