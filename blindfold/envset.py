"""Set one line in a dotenv file without showing the file.

Agents may not read or edit secret files, but often need to add a setting
that is not secret (a list of public app ids, a feature flag). This writes
`KEY=VALUE` and reports only the key and what happened, never the file's
contents or the value it replaced. It refuses a value that looks like a
secret, by the same rules the masker uses, and it never replaces a value that
looks like one: secrets stay the user's to change. Nothing here may print a
line of the file.
"""

import os
import re
import stat
import tempfile
from typing import List, Optional, Tuple

from .runtime import load_runtime

KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A dotenv file by name: .env, .env.local, prod.env, .envrc.
_DOTENV_NAME = re.compile(r"^(?:\.env(?:rc)?(?:\..+)?|.+\.env)$")
# Written bare; anything else is single-quoted.
_PLAIN = re.compile(r"[A-Za-z0-9_./:,@+%-]*")


class Refused(Exception):
    pass


def _line_key(line: str) -> Optional[Tuple[str, str]]:
    """(export prefix, key) of an assignment line, or None."""
    match = re.match(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)\s*=", line)
    return (match.group(1), match.group(2)) if match else None


def _quoted(value: str) -> str:
    if _PLAIN.fullmatch(value):
        return value
    if "'" in value:
        raise Refused("the value has both characters that need quoting and a single quote; ask the user to set it")
    return f"'{value}'"


def _protected_target(path: str) -> bool:
    """Whether the file is part of blindfold itself or an agent's settings."""
    from .selfguard import PROTECTED, SETTINGS

    for root in PROTECTED + SETTINGS:
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


def set_line(path: str, key: str, value: str, runtime=None) -> str:
    """Add or replace KEY in a dotenv file. Returns what happened, naming only the key."""
    if not KEY.fullmatch(key):
        raise Refused(f"{key!r} is not a variable name")
    if any(c in value for c in "\r\n\0"):
        raise Refused("the value spans lines; ask the user to set it")
    real = os.path.realpath(os.path.expanduser(path))
    if not _DOTENV_NAME.match(os.path.basename(real)):
        raise Refused(f"{path} isn't a dotenv file (.env, .env.*, *.env, .envrc)")
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
    lines = text.splitlines(keepends=True)
    found = [i for i, old in enumerate(lines) if (_line_key(old) or ("", ""))[1] == key]
    if len(found) > 1:
        raise Refused(f"{key} is set {len(found)} times in {path}; ask the user to fix it")
    if found:
        at = found[0]
        old = lines[at].rstrip("\r\n")
        prefix = _line_key(old)[0]
        rest = old.split("=", 1)[1].strip()
        if rest[:1] in ("'", '"') and (len(rest) < 2 or not rest.endswith(rest[0])):
            raise Refused(f"{key}'s current value spans lines; ask the user to change it")
        bare = rest.strip("'\"")
        if _looks_secret(rules, old) or _looks_secret(rules, bare) or any(v == bare and n != key for v, n in known):
            raise Refused(f"{key}'s current value looks like a secret; ask the user to change it")
        new = prefix + line
        if old == new:
            return f"{key} unchanged in {path}"
        lines[at] = new + lines[at][len(old):]
        result = f"{key} replaced in {path}"
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += "\n"
        lines.append(line + "\n")
        result = f"{key} added to {path}" + ("" if exists else " (new file)")
    _write(real, "".join(lines), exists)
    return result


def _write(path: str, text: str, exists: bool) -> None:
    """Atomically, keeping the file's mode; a new file is private."""
    mode = stat.S_IMODE(os.stat(path).st_mode) if exists else 0o600
    folder = os.path.dirname(path)
    fd, temp = tempfile.mkstemp(dir=folder, prefix=".blindfold-env-set-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise
