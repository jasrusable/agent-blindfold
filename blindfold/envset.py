"""Set one line in a dotenv file without showing the file.

Agents may not read or edit secret files, but often need to add a setting
that is not secret (a list of public app ids, a feature flag). This writes
`KEY=VALUE` and reports only the key and what happened, never the file's
contents or the value it replaced. It refuses a value that looks like a
secret, by the same rules the masker uses. No rule can be sure an old value
isn't a secret, so before replacing one it keeps the previous file beside it
as FILE.blindfold-bak, a protected name agents can't read. Nothing here may
print a line of the file.
"""

import os
import re
import stat
import tempfile
from typing import List, Optional, Tuple

from .runtime import load_runtime

KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A dotenv file by name: .env, .env.local, prod.env. Not .envrc, which is shell.
_DOTENV_NAME = re.compile(r"^(?:\.env(?:\..+)?|.+\.env)$")
# Keys that change what programs run or how blindfold works, wherever the file is loaded.
_RISKY_KEY = re.compile(
    r"^(?:PATH|BASH_ENV|ENV|ZDOTDIR|SHELL|HOME|CDPATH|IFS|PROMPT_COMMAND|NODE_OPTIONS|NODE_PATH|PERL5OPT|PERL5LIB"
    r"|RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|BLINDFOLD_.*|LD_.*|DYLD_.*|PYTHON.*|GIT_.*)$",
    re.IGNORECASE,
)
# Written bare; anything else is single-quoted.
_PLAIN = re.compile(r"[A-Za-z0-9_./:,@+%-]*")
# Control characters and the Unicode line and paragraph separators.
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f\x85  ]")
_ASSIGNMENT = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)\s*([=:])")
BACKUP_SUFFIX = ".blindfold-bak"
_TEMP_SUFFIX = ".blindfold-tmp"
# These hold a copy of the file, so agents may not read them either (see guards).
PROTECTED_COPIES = ["*" + BACKUP_SUFFIX, "*" + _TEMP_SUFFIX + "*"]


class Refused(Exception):
    pass


def _quoted(value: str) -> str:
    if _PLAIN.fullmatch(value):
        return value
    if "'" in value:
        raise Refused("the value has both characters that need quoting and a single quote; ask the user to set it")
    return f"'{value}'"


def _unclosed_quote(rest: str) -> Optional[str]:
    """The quote a value opens and doesn't close on its line, or None."""
    if rest[:1] not in ("'", '"'):
        return None
    quote, i = rest[0], 1
    while i < len(rest):
        if rest[i] == "\\" and quote == '"':
            i += 2
            continue
        if rest[i] == quote:
            return None
        i += 1
    return quote


def _assignments(lines: List[str]) -> List[Tuple[int, str, str, str]]:
    """(line index, prefix, key, separator) of each assignment, skipping lines
    inside a quoted value over several lines. Refuses a quote left open."""
    found, open_quote = [], None
    for i, line in enumerate(lines):
        if open_quote:
            if open_quote in line.replace('\\"', "") if open_quote == '"' else open_quote in line:
                open_quote = None
            continue
        match = _ASSIGNMENT.match(line.lstrip("﻿") if i == 0 else line)
        if not match:
            continue
        found.append((i, match.group(1), match.group(2), match.group(3)))
        open_quote = _unclosed_quote(line[match.end():].strip())
    if open_quote:
        raise Refused("the file has a quoted value that never closes; ask the user to fix it")
    return found


def _protected_target(path: str) -> bool:
    """Whether the file is part of blindfold itself, wherever it runs from, or an agent's settings."""
    from .cli import installed_hooks
    from .selfguard import PROTECTED, SETTINGS

    installed = [os.path.dirname(os.path.dirname(os.path.realpath(p))) for p in installed_hooks().values() if p]
    for root in PROTECTED + SETTINGS + installed:
        root = os.path.realpath(os.path.expanduser(root))
        if path == root or path.startswith(root + os.sep):
            return True
    return False


def _looks_secret(masker, text: str) -> List[str]:
    return sorted({finding.kind for finding in masker.mask(text)[1]})


def _judges(runtime):
    """The full masker for the new value, and for the old one the rules alone
    plus known values under other names: every value in a dotenv file is a
    known secret under its own name, so that alone says nothing."""
    from .mask import Masker

    config = runtime.config
    rules = Masker(
        key=b"envset", entropy=config.entropy, min_entropy=config.min_entropy,
        allow=config.allow, allow_ids=config.allow_ids, disabled_rules=config.disabled_rules,
    )
    known = [(s.value, s.name) for s in runtime.known.secrets if not s.weak]
    return runtime.masker, rules, known


def set_line(path: str, key: str, value: str, runtime=None, environ=None) -> str:
    """Add or replace KEY in a dotenv file. Returns what happened, naming only the key."""
    from .rules import is_secret_name

    environ = os.environ if environ is None else environ
    if any(name in environ for name in ("BLINDFOLD_CONFIG", "BLINDFOLD_HOME")):
        raise Refused("BLINDFOLD_CONFIG or BLINDFOLD_HOME is set, so the checks may not be the user's; unset it")
    if not KEY.fullmatch(key):
        raise Refused(f"{key!r} is not a variable name")
    if _RISKY_KEY.match(key):
        raise Refused(f"{key} changes what programs run; ask the user to set it")
    if _UNSAFE_CHARS.search(value):
        raise Refused("the value has a line break or control character; ask the user to set it")
    real = os.path.realpath(os.path.expanduser(path))
    if not _DOTENV_NAME.match(os.path.basename(real)):
        raise Refused(f"{path} isn't a dotenv file (.env, .env.*, *.env)")
    if _protected_target(real):
        raise Refused(f"{path} is part of blindfold or the agent's settings")
    masker, rules, known = _judges(runtime or load_runtime())
    line = f"{key}={_quoted(value)}"
    kinds = _looks_secret(masker, line) or _looks_secret(masker, value)
    if kinds:
        raise Refused(f"the value for {key} looks like a secret ({', '.join(kinds)}); ask the user to set it")

    exists = os.path.exists(real)
    text = ""
    if exists:
        with open(real, encoding="utf-8", newline="") as handle:
            text = handle.read()
    # Lines end at \n only, as dotenv parsers read them.
    lines = text.split("\n")
    found = [a for a in _assignments(lines) if a[2] == key]
    if len(found) > 1:
        raise Refused(f"{key} is set {len(found)} times in {path}; ask the user to fix it")
    if found:
        at, prefix, _, separator = found[0]
        old = lines[at]
        if separator != "=" or _unclosed_quote(old.split(separator, 1)[1].strip()):
            raise Refused(f"{key} is written in a form this can't replace; ask the user to change it")
        if is_secret_name(key):
            raise Refused(f"{key} is named like a secret; ask the user to change it")
        rest = old.split("=", 1)[1].strip()
        bare = rest.strip("'\"")
        if _looks_secret(rules, old) or _looks_secret(rules, bare) or any(v == bare and n != key for v, n in known):
            raise Refused(f"{key}'s current value looks like a secret; ask the user to change it")
        ending = "\r" if old.endswith("\r") else ""
        new = old[: len(old) - len(old.lstrip("﻿"))] + prefix.lstrip("﻿") + line + ending
        if old == new:
            return f"{key} unchanged in {path}"
        lines[at] = new
        _write(real + BACKUP_SUFFIX, text, 0o600)
        result = f"{key} replaced in {path} (previous file kept as {os.path.basename(real)}{BACKUP_SUFFIX})"
    else:
        if lines[-1] == "":
            lines.pop()
        lines += [line, ""]
        result = f"{key} added to {path}" + ("" if exists else " (new file)")
    _write(real, "\n".join(lines), stat.S_IMODE(os.stat(real).st_mode) if exists else 0o600)
    return result


def _write(path: str, text: str, mode: int) -> None:
    """Atomically, under a name agents may not read until it lands."""
    fd, temp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=os.path.basename(path), suffix=_TEMP_SUFFIX)
    try:
        os.chmod(temp, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temp, path)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise
