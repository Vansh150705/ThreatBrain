"""Prompt-injection hardening helpers shared by every agent.

Security events carry attacker-controlled text (usernames, URLs, command lines,
HTTP headers, log lines, threat-feed comments). All of it is untrusted. Agents
build prompts in the shape ``<data lines> ... TASK: <instructions>``; the data
portion is fenced in ``<untrusted_data>`` tags and the system prompt tells the
model that fenced content is to be analysed, never obeyed. This is a mitigation,
not a guarantee: sensitive actions are additionally validated server-side (see
the Response agent) and gated by human approval.
"""

from __future__ import annotations

import re

TASK_MARKER = "\nTASK:\n"
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TAG = re.compile(r"</?\s*untrusted_data[^>]*>", re.IGNORECASE)


def sanitize_text(text: str) -> str:
    """Remove control characters and any attempt to forge/close our fence."""
    return _TAG.sub("[tag-removed]", _CONTROL.sub("", text))


def fence_untrusted(prompt: str, extra_context: str | None = None) -> str:
    """Wrap the data portion of ``prompt`` (everything before ``TASK:``).

    ``extra_context`` (e.g. results of earlier agents) is placed inside the fence,
    right before the task, so it is treated as data too.
    """
    idx = prompt.find(TASK_MARKER)
    if idx == -1:
        # Short fixed prompts ("incident not found...") contain no external data.
        return prompt if not extra_context else prompt + "\n\n" + sanitize_text(extra_context)
    data, task = prompt[:idx], prompt[idx:]
    if extra_context:
        data = data.rstrip() + "\n\n" + extra_context
    return f"<untrusted_data>\n{sanitize_text(data)}\n</untrusted_data>{task}"
