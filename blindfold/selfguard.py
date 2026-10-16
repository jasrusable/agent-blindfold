"""Refuse tool calls that would change blindfold itself: the installed copy that
is running, its config and key, its skill links, its entries in the agents'
settings, or a switch that turns hooks off. An agent tidying settings, or a
stray git command, must not quietly turn masking off; the user makes those
changes. Like the command denylist, this guards against accidents, not intent,
and it judges real use, not mentions: notes or docs that name a path are fine.
"""

import os
import re
from typing import Any, Dict, Iterable, List, Optional

from . import shell
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
# Claude Code's setting that turns every hook off. Assembled, so this file
# doesn't trip an installed copy of this guard when it is edited.
DISABLE_HOOKS = "disable" + "AllHooks"

_PATH_KEYS = ("file_path", "filePath", "path", "target_file", "targetFile", "notebook_path")
_OLD_TEXT_KEYS = ("old_string", "oldString", "old_str")
_HOOK_COMMAND = re.compile(r"[^\s\"']*blindfold(?: [^\s\"']+){0,4} hook")
_SETTINGS_FILE = re.compile(r"(?:^|/)settings(?:\.local)?\.json$")

# Parts of a shell command that only read: allowed even on a protected path.
_READ_ONLY = re.compile(
    r"(?:cd|ls|cat|head|tail|less|grep|egrep|wc|stat|file|diff|readlink|realpath|test|\[|echo|printf|jq)(?:\s.*)?"
    r"|find(?:\s(?:(?!-delete|-exec|-ok|-fprint|-fls).)*)?"
    r"|git(?:\s+-C\s+\S+)?\s+(?:status|log|show|diff|rev-parse|branch|describe)(?:\s.*)?"
    r"|\S*blindfold\s+(?:doctor|scan|hook|selftest|install(?!.*--apply))(?:\s.*)?",
    re.DOTALL,
)
# Commands that act on input from an earlier part: `find <path> | xargs rm`.
_CONSUMERS = ("xargs", "parallel", "sh", "bash", "zsh", "while", "source", ".")
_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
_HARMLESS_REDIRECT = re.compile(r"\d?>&\d|\d?>\s*/dev/null")


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


def _named(text: str, roots: Iterable[str]) -> Optional[str]:
    return next((root for root in roots for form in _cached_spellings(root) if form in text), None)


_SPELLINGS: Dict[str, List[str]] = {}


def _cached_spellings(path: str) -> List[str]:
    """_spellings resolves symlinks; once per path per hook run is enough."""
    if path not in _SPELLINGS:
        _SPELLINGS[path] = _spellings(path)
    return _SPELLINGS[path]


def _is_read_only_part(part: str) -> bool:
    if "`" in part or "$(" in part or "\n" in part:
        return False
    bare = _QUOTED.sub("Q", part)
    if ">" in _HARMLESS_REDIRECT.sub("", bare) or "'" in bare or '"' in bare:
        return False
    return bool(_READ_ONLY.fullmatch(bare.strip()))


def is_read_only_command(command: str) -> bool:
    return all(_is_read_only_part(part) for part in shell.parts(command))


def _writes_only_elsewhere(part: str, roots: List[str]) -> bool:
    """A cat/tee/echo/printf whose output goes to files outside roots: what it
    says (a heredoc of notes naming a path) is data, not use."""
    line = shell.first_line(part)
    if shell.head(line) not in shell.DATA_COMMANDS or "`" in line or "$(" in line:
        return False
    targets = shell.write_targets(part)
    return bool(targets) and not any(_named(target, roots) or _inside(target, roots) for target in targets)


def _command_reason(command: str, cwd: Optional[str], protected: List[str], settings: List[str]) -> Optional[str]:
    guarded = protected + settings
    inside = _inside(cwd, protected) if cwd else None
    named_earlier: Optional[str] = None
    for part in shell.parts(command):
        line = shell.first_line(part)
        if named_earlier and shell.head(line) in _CONSUMERS:
            return f"it acts on {named_earlier} through {shell.head(line)}"
        named_earlier = named_earlier or _named(part, protected)
        if shell.head(line) == "cd":
            target = line.split(None, 1)[1].strip().strip("'\"") if len(line.split()) > 1 else "~"
            inside = _inside(target, protected) if not target.startswith("$") else inside
            continue
        if _is_read_only_part(part):
            continue
        if DISABLE_HOOKS in part and "settings" in part:
            return f"it sets {DISABLE_HOOKS}"
        if _writes_only_elsewhere(part, guarded):
            continue
        named = _named(part, protected)
        if named or inside:
            return f"it changes {named or inside}"
        if _named(part, settings):
            return "it may rewrite the agent settings; use the file-edit tool, which checks blindfold's hooks stay"
    return None


def _hook_commands(text: str) -> set:
    return set(_HOOK_COMMAND.findall(text))


def _read(path: str) -> str:
    try:
        with open(_resolve(path), encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


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


def _settings_change(tool_input: Dict[str, Any], path: str) -> bool:
    """An edit that touches blindfold's hook entries, or a full write that drops them."""
    if "content" in tool_input:
        return bool(_hook_commands(_read(path)) - _hook_commands(str(tool_input["content"])))
    old_texts = [text for key in _OLD_TEXT_KEYS for text in strings(_values_under(tool_input, key))]
    return any("blindfold" in text for text in old_texts)


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
    paths = [value for key in _PATH_KEYS for value in [tool_input.get(key)] if isinstance(value, str) and value]
    for path in paths:
        root = _inside(path, protected)
        if root:
            return f"it writes inside {root}"
        if _SETTINGS_FILE.search(path) and any(DISABLE_HOOKS in text for text in strings(tool_input)):
            return f"it sets {DISABLE_HOOKS}"
        if _inside(path, settings) and _settings_change(tool_input, path):
            return "it changes blindfold's hooks in the agent settings"
    return None
