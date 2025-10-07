from __future__ import annotations

import os
import json
from bisect import bisect_right
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple

from .patterns import PATTERNS

MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5MB safety cap per file
SAMPLE_BYTES = 4096

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


def dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for s in items:
        if not isinstance(s, str):
            continue
        t = s.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(s)
    return out


def _iter_texts_for_keys(value, allowed_keys: Sequence[str], allowed: bool = False) -> Iterator[str]:
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


def iter_user_texts(payload: Dict) -> Iterator[str]:
    if not isinstance(payload, dict):
        return iter(())

    # messages array with role/content
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

    # common flat keys
    for key in ("message", "input", "input_text", "prompt", "body", "text", "userMessage"):
        if key in payload:
            yield from _iter_texts_for_keys(payload[key], USER_MESSAGE_KEYS, True)


def extract_command_outputs(data) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []

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

    # dedupe by text
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for label, text in out:
        t = text.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        uniq.append((label or "content", text))
    return uniq


def scan_text(text: str, path: str):
    findings = []
    # precompute line starts for O(log n) line lookup
    line_starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(idx + 1)

    for pname, rx in PATTERNS.items():
        for m in rx.finditer(text):
            line_no = bisect_right(line_starts, m.start())
            findings.append({
                "file": path,
                "line": line_no,
                "type": pname,
                "match": m.group(0),
            })
    return findings


def scan_file(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File does not exist: {path}")
    if not should_scan_file(path):
        return []
    size = os.path.getsize(path)
    if size > MAX_SCAN_BYTES:
        raise RuntimeError(
            f"File size {size} bytes exceeds scan limit of {MAX_SCAN_BYTES} bytes"
        )
    with open(path, "rb") as f:
        blob = f.read()
    if is_probably_binary(blob):
        return []
    text = blob.decode("utf-8", "ignore")
    return scan_text(text, path)


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

