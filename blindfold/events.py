"""One view of a hook event, whichever agent sent it.

Claude Code sends snake_case keys. Grok sends camelCase keys plus Claude's
snake_case twins (with Claude's PascalCase event names), so reading the
snake_case key first and falling back to camelCase covers both.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .structure import strings

RESULT_KEYS = ("tool_response", "toolResult", "tool_result", "error")
# If an agent upgrade renames the result field, fall back to any field that
# reads like one rather than silently masking nothing.
_RESULT_HINTS = ("response", "result", "output")
READ_ONLY_TOOLS = frozenset({"Read", "Glob", "Grep", "LS", "read_file", "list_dir", "grep", "glob_file_search", "codebase_search"})


def _first(event: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in event:
            return event[key]
    return None


@dataclass(frozen=True)
class Event:
    raw: Dict[str, Any]

    @property
    def name(self) -> str:
        value = self.raw.get("hook_event_name")
        return value if isinstance(value, str) else ""

    @property
    def tool(self) -> str:
        value = _first(self.raw, "tool_name", "toolName")
        return value if isinstance(value, str) else ""

    @property
    def tool_input(self) -> Any:
        return _first(self.raw, "tool_input", "toolInput")

    @property
    def tool_input_texts(self) -> List[str]:
        return strings(self.tool_input)

    @property
    def result_key(self) -> Optional[str]:
        known = next((key for key in RESULT_KEYS if key in self.raw), None)
        if known is not None:
            return known
        return next((key for key in self.raw if any(hint in key.lower() for hint in _RESULT_HINTS)), None)

    @property
    def result_key_is_known(self) -> bool:
        return any(key in self.raw for key in RESULT_KEYS)

    @property
    def is_grok(self) -> bool:
        # Grok adds camelCase twins of every key; Claude Code sends snake_case only.
        return "hookEventName" in self.raw

    @property
    def result(self) -> Any:
        key = self.result_key
        return self.raw[key] if key else None

    @property
    def prompt_texts(self) -> List[str]:
        return strings([self.raw.get("prompt"), self.raw.get("userPrompt")])

    @property
    def last_message_texts(self) -> List[str]:  # Grok sends it; Claude may not
        return strings([self.raw.get("last_assistant_message"), self.raw.get("lastAssistantMessage")])

    @property
    def transcript_path(self) -> Optional[str]:
        value = _first(self.raw, "transcript_path", "transcriptPath")
        return value if isinstance(value, str) and value else None

    @property
    def is_read_only_tool(self) -> bool:
        return self.tool in READ_ONLY_TOOLS
