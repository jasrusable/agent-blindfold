"""Refusals beyond masking: calls that dump the environment, print a credential
variable, read a secret file outright, or switch off the secret scan.

Masking still runs on everything these let through. They exist because some
output can't be masked reliably (a whole environment holds values no rule
recognises) and because a secret file is better left unread than read and
masked. Like blocked_commands, they guard against accidents, not intent:
quoting tricks get past any denylist.
"""

import fnmatch
import os
import re
from typing import Any, Iterable, List, Optional

from . import shell
from .cli_paths import LAUNCHER
from .config import _COMMAND_START, Config

# Prints every variable, or the values a tool loads from a secret file.
_END = r"[ \t]*(?:$|[|;&)`>]|\d>|<)"
_EQUALS = r"[ \t]*(?:=|'='|\"=\")"
_NAMES_ONLY = (
    r"[ \t]*\|[ \t]*(?:cut[ \t]+(?:-d" + _EQUALS + r"[ \t]+-f[ \t]*1|-f[ \t]*1[ \t]+-d" + _EQUALS + r")[ \t]*(?=$|[|;&)])"
    r"|sed[ \t]+(?:-E[ \t]+)?['\"]s/=\.\*//['\"])"
)
ENV_DUMP_COMMANDS = [
    _COMMAND_START + r"printenv\b",
    # Not `env | cut -d= -f1` or `env | sed 's/=.*//'`: names only.
    _COMMAND_START + r"env(?!" + _NAMES_ONLY + r")" + _END,
    _COMMAND_START + r"(?:set|export|declare|typeset)(?:[ \t]+-[a-zA-Z]*[px][a-zA-Z]*)?" + _END,
    _COMMAND_START + r"(?:declare|typeset)[ \t]+-[a-zA-Z]*p",
    _COMMAND_START + r"direnv\s+(?:export|dump|show|exec)\b",
]
# A credential variable echoed or printed. `${#VAR}` (its length) and
# `${VAR:+set}` (whether it is set) don't print the value, so they pass.
_CREDENTIAL_VAR = (
    r"(?:DATABASE_URL|POSTGRES_URL|POSTGRES_PASSWORD|PG_?URL|PGPASSWORD|DB_URL|DB_PASSWORD"
    r"|[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*)"
)
CREDENTIAL_ECHO = _COMMAND_START + r"(?:echo|printf|print)\b[^|;&\n]*\$\{?" + _CREDENTIAL_VAR + r"\b(?!:?[+?])"

# Read outright: refused for file tools and for commands naming them. A
# pattern with a / is a path (~ allowed); one without is a file name anywhere.
DEFAULT_PROTECTED_FILES = [
    "~/.config/*/*.env",
    "~/.config/*/.env",
    ".envrc",
    ".envrc.local",
    "*.p8",
    ".netrc",
    ".netrc.gpg",
]
# Committed templates hold fake values.
_TEMPLATE = re.compile(r"\.(?:example|sample|template|dist|test)$", re.IGNORECASE)
# Commands that name a file without printing it.
_HARMLESS_HEADS = frozenset({"ls", "test", "[", "stat", "chmod", "direnv", "touch"})
_PATH_KEYS = ("file_path", "filePath", "path", "target_file", "target_directory", "notebook_path")
# Hooks paths that put the secret scan back rather than bypass it.
_RESTORED_HOOKS = re.compile(r"^(?:\./)?\.husky(?:/_)?/?$")
_COMMIT_ARG_LETTERS = set("mFCct")
_COMMIT_ARG_OPTIONS = {
    "--message", "--file", "--author", "--date", "--template", "--reuse-message", "--reedit-message",
    "--fixup", "--squash", "--cleanup", "--trailer", "--pathspec-from-file",
}

ENV_DUMP_REASON = (
    "blindfold: this command prints the whole environment (or the values direnv loads), which holds secrets no "
    "rule can recognise. Check one variable without printing it: `test -n \"${NAME:+set}\"`, `echo ${#NAME}`, or "
    "list names only with `compgen -v`."
)
CREDENTIAL_ECHO_REASON = (
    "blindfold: this command prints a credential variable's value. Check it without printing it "
    "(`test -n \"${NAME:+set}\"`, `echo ${#NAME}`), or pass it straight to the tool that needs it."
)
PROTECTED_FILE_REASON = (
    "blindfold: {path} is a secret file, so agents don't read, edit or print it, even masked. Refer to its "
    "variables by name. To set a line that isn't secret, run `{launcher} env-set FILE KEY VALUE`; for anything "
    "else, ask the user to make the change (they can type `! <command>`)."
)
SCAN_BYPASS_REASON = (
    "blindfold: this command switches off the git hooks that scan commits for secrets ({how}). Fix what the hook "
    "reports instead, or ask the user to run it."
)


def _protected_patterns(config: Config) -> List[str]:
    defaults = DEFAULT_PROTECTED_FILES if config.protect_secret_files else []
    return [*defaults, *config.extra_protected_files]


def protected_match(path: str, patterns: Iterable[str], cwd: Optional[str] = None) -> Optional[str]:
    """The protected pattern a path falls under, or None."""
    if not path or _TEMPLATE.search(path):
        return None
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded) and cwd:
        expanded = os.path.join(cwd, expanded)
    full = os.path.normpath(expanded)
    name = os.path.basename(full)
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatchcase(full, os.path.normpath(os.path.expanduser(pattern))):
                return pattern
        elif fnmatch.fnmatchcase(name, pattern):
            return pattern
    return None


def _scan_bypass(texts: List[str]) -> Optional[str]:
    """How a command's words switch off the commit hooks, or None."""
    lowered = [text.lower() for text in texts]
    if "--no-verify" in texts:
        return "--no-verify"
    if any(text == "HUSKY=0" for text in texts):
        return "HUSKY=0"
    if "git" not in [os.path.basename(text) for text in texts]:
        return None
    for text in lowered:
        if text.startswith("core.hookspath=") or text.startswith("-ccore.hookspath="):
            if not _RESTORED_HOOKS.match(text.split("=", 1)[1]):
                return "a core.hooksPath override"
    if "config" in lowered and "core.hookspath" in lowered:
        at = lowered.index("core.hookspath")
        rest = [t for t in texts[at + 1 :] if not t.startswith("-")]
        if any(t in ("--unset", "--unset-all") for t in lowered) or (rest and not _RESTORED_HOOKS.match(rest[0])):
            return "a core.hooksPath change"
    if "commit" in lowered:
        expects_argument = False
        for text in texts[lowered.index("commit") + 1 :]:
            if expects_argument:
                expects_argument = False
                continue
            if text == "--":
                break
            if text.startswith("--"):
                expects_argument = text in _COMMIT_ARG_OPTIONS
                continue
            if re.match(r"^-[A-Za-z]+$", text):
                for index, letter in enumerate(text[1:]):
                    if letter == "n":
                        return "git commit -n"
                    if letter in _COMMIT_ARG_LETTERS:
                        expects_argument = index == len(text) - 2
                        break
    return None


def _is_env_set(texts: List[str]) -> bool:
    """`blindfold env-set FILE KEY VALUE`: writes one line and never shows the file."""
    args = [text for text in texts[1:] if not text.startswith("-")]
    return bool(texts) and os.path.basename(texts[0]) == "blindfold" and args[:1] == ["env-set"]


def _word_reason(text: str, cwd: Optional[str], patterns: List[str], config: Config, depth: int) -> Optional[str]:
    for part, body, _ in shell.segments(text):
        parsed = shell.words(part)
        if parsed is not None:
            texts = [word.text for word in parsed[0] if not word.op]
            if config.block_secret_scan_bypass:
                how = _scan_bypass(texts)
                if how:
                    return SCAN_BYPASS_REASON.format(how=how)
            if config.block_env_dumps and any(re.match(r"^/proc/(?:self|\d+|\$\$|\*)/environ$", t) for t in texts):
                return ENV_DUMP_REASON
            head = shell.head(part)
            if head not in _HARMLESS_HEADS and not (_is_env_set(texts) and not shell.runs_substitution(part)):
                for word in texts[1:] if texts else []:
                    candidates = [word] + ([word.split("=", 1)[1]] if "=" in word else [])
                    for candidate in candidates:
                        if protected_match(candidate, patterns, cwd):
                            return PROTECTED_FILE_REASON.format(path=candidate, launcher=LAUNCHER)
        # A body still here is one that may run (strip_data_heredocs kept it).
        if body and depth < 3:
            found = _word_reason(body, cwd, patterns, config, depth + 1)
            if found:
                return found
    return None


def command_reason(command: str, cwd: Optional[str], config: Config) -> Optional[str]:
    judged = shell.strip_data_heredocs(command)
    run = shell.strip_non_commands(command)
    if config.block_env_dumps and any(re.search(p, run, re.MULTILINE) for p in ENV_DUMP_COMMANDS):
        return ENV_DUMP_REASON
    if config.block_env_dumps and re.search(CREDENTIAL_ECHO, run, re.MULTILINE):
        return CREDENTIAL_ECHO_REASON
    return _word_reason(judged, cwd, _protected_patterns(config), config, 0)


def reason(tool_input: Any, cwd: Optional[str], config: Config) -> Optional[str]:
    """Why this call is refused by these guards, or None."""
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if isinstance(command, str):
        return command_reason(command, cwd, config)
    patterns = _protected_patterns(config)
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and protected_match(value, patterns, cwd):
            return PROTECTED_FILE_REASON.format(path=value, launcher=LAUNCHER)
    return None


def claude_deny_rules(config: Config) -> List[str]:
    """The protected files as Claude Code permission rules: a second line that
    holds even where a hook doesn't run."""
    rules = []
    for pattern in _protected_patterns(config):
        target = pattern if "/" in pattern else f"**/{pattern}"
        if target.startswith("/"):
            target = "/" + target
        rules += [f"Read({target})", f"Edit({target})"]
    return rules
