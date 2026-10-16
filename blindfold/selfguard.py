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
# Agent settings files, wherever they are: settings.json, settings.local.json,
# managed-settings.json, anything under a .claude directory.
_SETTINGS_FILE = re.compile(r"settings[^/]*\.json$|(?:^|/)\.claude/", re.IGNORECASE)

# Parts of a shell command that only read: allowed even on a protected path.
_READ_ONLY = re.compile(
    r"(?:cd|ls|cat|head|tail|less|grep|egrep|wc|stat|file|diff|readlink|realpath|test|\[|echo|printf|jq)(?:\s.*)?"
    r"|find(?:\s(?:(?!-delete|-exec|-ok|-fprint|-fls).)*)?"
    r"|git(?:\s+-C\s+\S+)?\s+(?:status|log|show|diff|rev-parse|branch|describe)(?:\s.*)?"
    r"|\S*blindfold\s+(?:doctor|scan|hook|selftest|install(?!.*--apply))(?:\s.*)?",
    re.DOTALL,
)
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


def _data_targets(part: str, here: Optional[str]) -> Optional[List[str]]:
    """The files a plain cat/tee/echo/printf writes, resolved against here, or
    None if the part is anything else: what such a part says (a heredoc of
    notes naming a path) is data, not use."""
    line = shell.first_line(part)
    if shell.head(line) not in shell.DATA_COMMANDS or shell.runs_substitution(part):
        return None
    targets = shell.write_targets(part)
    if not targets or not all(shell.is_plain_file(t) for t in targets):
        return None
    base = here or os.getcwd()
    return [os.path.join(base, os.path.expanduser(t)) for t in targets]


def _cd(line: str, here: Optional[str], protected: List[str]) -> Optional[str]:
    """The directory after `cd …`, or None if it can't be known. A target that
    names a protected path counts as inside it, however it's spelled."""
    words = line.split()
    target = os.path.expandvars(os.path.expanduser(words[1].strip("'\""))) if len(words) > 1 else os.path.expanduser("~")
    if any(mark in target for mark in ("$", "`", "(")) or target == "-":
        named = _named(line, protected)
        return _resolve(named) if named else None
    return os.path.normpath(os.path.join(here, target)) if here and not os.path.isabs(target) else os.path.abspath(target)


def _command_reason(command: str, cwd: Optional[str], protected: List[str], settings: List[str]) -> Optional[str]:
    """Deny by default: once a command names a protected path, or runs inside
    one, every part must be read-only or a plain data write elsewhere."""
    guarded = protected + settings
    names_protected = _named(command, protected)
    here = cwd
    for part in shell.parts(command):
        line = shell.first_line(part)
        if shell.head(line) == "cd":
            here = _cd(line, here, protected)
            continue
        if _is_read_only_part(part):
            continue
        targets = _data_targets(part, here)
        elsewhere = targets is not None and not any(_named(t, guarded) or _inside(t, guarded) for t in targets)
        if DISABLE_HOOKS.lower() in part.lower() and not (elsewhere and not any(_SETTINGS_FILE.search(t) for t in targets or [])):
            return f"it sets {DISABLE_HOOKS}"
        if elsewhere:
            continue
        inside = _inside(here, protected) if here else None
        if inside or names_protected:
            return f"it changes {inside or names_protected}"
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
        if _SETTINGS_FILE.search(path) and any(DISABLE_HOOKS.lower() in text.lower() for text in strings(tool_input)):
            return f"it sets {DISABLE_HOOKS}"
        if _inside(path, settings) and _settings_change(tool_input, path):
            return "it changes blindfold's hooks in the agent settings"
    return None
