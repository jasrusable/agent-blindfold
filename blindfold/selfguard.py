"""Refuse tool calls that would change blindfold itself: the installed copy that
is running, its config and key, its skill links, its entries in the agents'
settings, or a switch that turns hooks off. An agent tidying settings, or a
stray git command, must not quietly turn masking off; the user makes those
changes. Like the command denylist, this guards against accidents, not intent.
"""

import os
import re
from typing import Any, Dict, Iterable, List, Optional

from .cli_paths import REPO
from .config import CONFIG_DIR
from .structure import strings

PROTECTED = [
    REPO,
    CONFIG_DIR,
    "~/.claude/skills/blindfold",
    "~/.grok/skills/blindfold",
    "~/.grok/hooks/blindfold.json",
]
SETTINGS = ["~/.claude/settings.json", "~/.claude/settings.local.json"]
DISABLE_HOOKS = "disableAllHooks"

_PATH_KEYS = ("file_path", "filePath", "path", "target_file", "targetFile", "notebook_path")
_OLD_TEXT_KEYS = ("old_string", "oldString", "old_str")
_HOOK_COMMAND = re.compile(r"[^\s\"']*blindfold(?: [^\s\"']+){0,4} hook")

# A shell command touching a protected path is allowed only if every part of it
# is one of these read-only forms.
_READ_ONLY_PART = re.compile(
    r"\s*(?:"
    r"(?:cd|ls|cat|head|tail|less|grep|egrep|wc|stat|file|diff|readlink|realpath|test|\[|echo|printf|jq)(?:\s.*)?"
    r"|find(?:\s(?:(?!-delete|-exec|-ok|-fprint|-fls).)*)?"
    r"|git(?:\s+-C\s+\S+)?\s+(?:status|log|show|diff|rev-parse|branch|describe)(?:\s.*)?"
    r"|\S*blindfold\s+(?:doctor|scan|hook|selftest|install(?!.*--apply))(?:\s.*)?"
    r")\s*"
)
_HARMLESS_REDIRECT = re.compile(r"\d?>&\d|\d?>\s*/dev/null")
# Quoted text is literal to the shell (except substitution, checked on the raw
# command), so a | or > inside a grep pattern doesn't split or redirect. An
# unbalanced quote stays in place and makes the command look unsafe.
_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def _resolve(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def _inside(path: str, roots: Iterable[str]) -> Optional[str]:
    target = _resolve(path)
    return next((root for root in roots if target == _resolve(root) or target.startswith(_resolve(root) + os.sep)), None)


def _spellings(path: str) -> List[str]:
    """How a command might name path: absolute, ~/…, $HOME/…, ${HOME}/…"""
    absolute = _resolve(path)
    home = os.path.expanduser("~")
    forms = {absolute, os.path.abspath(os.path.expanduser(path))}
    for form in list(forms):
        if form.startswith(home + os.sep):
            rest = form[len(home):]
            forms |= {"~" + rest, "$HOME" + rest, "${HOME}" + rest}
    return sorted(forms)


def is_read_only_command(command: str) -> bool:
    if "`" in command or "$(" in command:
        return False
    bare = _QUOTED.sub("Q", command)
    if ">" in _HARMLESS_REDIRECT.sub("", bare) or "'" in bare or '"' in bare:
        return False
    parts = re.split(r"&&|\|\||[;|\n]", bare)
    return all(_READ_ONLY_PART.fullmatch(part) for part in parts if part.strip())


def _hook_commands(text: str) -> set:
    return set(_HOOK_COMMAND.findall(text))


def _read(path: str) -> str:
    try:
        with open(_resolve(path), encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _settings_change(tool_input: Dict[str, Any], path: str) -> bool:
    """An edit that touches blindfold's hook entries, or a full write that drops them."""
    if "content" in tool_input:
        return bool(_hook_commands(_read(path)) - _hook_commands(str(tool_input["content"])))
    old_texts = [text for key in _OLD_TEXT_KEYS for text in strings(_values_under(tool_input, key))]
    return any("blindfold" in text for text in old_texts)


def _values_under(value: Any, key: str) -> List[Any]:
    found, stack = [], [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            found += [item for name, item in node.items() if name == key]
            stack += list(node.values())
        elif isinstance(node, list):
            stack += node
    return found


def _command_reason(command: str, cwd: Optional[str], protected: List[str], settings: List[str]) -> Optional[str]:
    if is_read_only_command(command):
        return None
    if DISABLE_HOOKS in command:
        return f"it sets {DISABLE_HOOKS}"
    named = next((root for root in protected for form in _spellings(root) if form in command), None)
    if named:
        return f"it touches {named}"
    if cwd and _inside(cwd, protected):
        return f"it runs inside {_inside(cwd, protected)}"
    # A shell rewrite can drop the hooks without naming them; the file-edit
    # tools are checked precisely, so settings changes go through those.
    if any(form in command for path in settings for form in _spellings(path)):
        return "it may rewrite the agent settings; use the file-edit tool, which checks blindfold's hooks stay"
    return None


def reason(
    tool_input: Any, read_only_tool: bool, cwd: Optional[str] = None,
    protected: Optional[List[str]] = None, settings: Optional[List[str]] = None,
) -> Optional[str]:
    """Why this call would change blindfold itself, or None."""
    protected = PROTECTED if protected is None else protected
    settings = SETTINGS if settings is None else settings
    if read_only_tool or not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if isinstance(command, str):
        return _command_reason(command, cwd, protected, settings)
    if any(DISABLE_HOOKS in text for text in strings(tool_input)):
        return f"it sets {DISABLE_HOOKS}"
    paths = [value for key in _PATH_KEYS for value in [tool_input.get(key)] if isinstance(value, str) and value]
    for path in paths:
        root = _inside(path, protected)
        if root:
            return f"it writes inside {root}"
        if _inside(path, settings) and _settings_change(tool_input, path):
            return "it changes blindfold's hooks in the agent settings"
    return None
