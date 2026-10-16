"""Exact values of secrets blindfold has been told about.

Matching a known value is deterministic: once a secret's file is listed, that
value is masked wherever it shows up, whatever its shape, and so are its
common encodings (base64, URL encoding, JSON escaping). The files are read
fresh on every call (a hook is a new process each time), so a rotated or new
secret is picked up immediately. Values are held only in memory.
"""

import base64
import glob
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from .rules import PLACEHOLDER_VALUE, is_secret_name, shannon_entropy

ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*?)\s*$")
URL_PASSWORD = re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]*:([^@/\s]+)@", re.IGNORECASE)
PLAIN_URL = re.compile(r"^[a-z][a-z0-9+.-]*://[^@\s]*$", re.IGNORECASE)
NUMBER = re.compile(r"^[0-9.,:_-]+$")
# A filesystem path, e.g. $PWD: `pwd` names a password in config but the
# working directory in the shell, and a path in every tool call isn't a secret.
ABSOLUTE_PATH = re.compile(r"^(?:/|~/|\.{1,2}/|[A-Za-z]:\\)[^\s]*$")
# A path or label, not a credential: lowercase path segments (alias/app,
# uploads/images), a key file (certs/key.pem), a snake/kebab label (user_profile_v2).
_PATH_OR_LABEL = re.compile(r"^[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+$|\.(?:pem|key|crt|cer|p12|pfx|json|ya?ml|txt)$|^[a-z]+(?:[_-][a-z0-9]{1,12})+$")
_WORD_LIKE = re.compile(r"[A-Za-z]+[0-9]{0,4}")
# Shell state, never secrets, whatever their names suggest.
SHELL_STATE = frozenset({"PWD", "OLDPWD", "HOME", "PATH", "SHELL", "USER", "LOGNAME", "TMPDIR", "TERM", "LANG", "_"})


@dataclass(frozen=True)
class KnownSecret:
    value: str
    name: str
    # A word-like value (a dictionary word, maybe with a few digits): masked
    # only as a whole word, and never a reason to refuse a call or raise the
    # rotate alarm, since it also appears in ordinary text.
    weak: bool = False


# A dotenv value: quoted (the quotes end it, a comment may follow) or bare (a
# ` #` starts a comment).
_QUOTED_VALUE = re.compile(r"""^(["'`])(.*?)\1(?:\s+#.*)?$""", re.DOTALL)


def _unquote(raw: str) -> str:
    value = raw.strip()
    quoted = _QUOTED_VALUE.match(value)
    if quoted:
        return quoted.group(2)
    hash_at = value.find(" #")
    return value[:hash_at].rstrip() if hash_at >= 0 else value


# Longer values are skipped to bound the known-value regex; a value this long is
# a key file, whose lines are known values of their own.
MAX_KNOWN_LENGTH = 8192


def is_weak(value: str) -> bool:
    return bool(_WORD_LIKE.fullmatch(value))


def is_secret_value(name: str, value: str, min_length: int) -> bool:
    if not min_length <= len(value) <= MAX_KNOWN_LENGTH:
        return False
    if PLACEHOLDER_VALUE.match(value) or NUMBER.match(value) or PLAIN_URL.match(value) or ABSOLUTE_PATH.match(value):
        return False
    # A short word-like value (postgres, development, password1) would hide that
    # word everywhere. Rules still mask it where it is assigned to a secret name.
    if is_weak(value) and len(value) < 12:
        return False
    if is_secret_name(name):
        return True
    # SMTP_PASS, MAILGUN_KEY: a short-form name counts, but not for a path or a
    # label (SSL_KEY=certs/key.pem, CACHE_KEY=user_profile_v2).
    if is_secret_name(name, strong=True):
        return not _PATH_OR_LABEL.search(value)
    # An unlabelled value counts only when it is long and random enough that it
    # can't be an ordinary word, path or setting that also shows up in output.
    return len(value) >= 20 and shannon_entropy(value) >= 3.8 and not re.search(r"[\s/]", value)


def _env_entries(text: str) -> List[Tuple[str, str]]:
    """(name, raw value) pairs; a quoted value may span lines (a PEM key)."""
    entries, lines, at = [], text.splitlines(), 0
    while at < len(lines):
        line, at = lines[at], at + 1
        match = None if line.lstrip().startswith("#") else ENV_LINE.match(line)
        if not match:
            continue
        raw = match.group(2).strip()
        quote = raw[:1]
        if quote in ("'", '"') and quote not in raw[1:]:
            rest = []
            while at < len(lines) and quote not in lines[at]:
                rest.append(lines[at])
                at += 1
            if at < len(lines):
                rest.append(lines[at][: lines[at].index(quote) + 1])
                at += 1
            raw = "\n".join([raw, *rest])
        entries.append((match.group(1), raw))
    return entries


def _key_lines(value: str) -> List[str]:
    """The body lines of a multi-line value, which output often shows one at a
    time. PEM BEGIN/END lines are public boilerplate, never secrets."""
    return [line.strip() for line in value.splitlines() if line.strip() and not line.lstrip().startswith("-----")] if "\n" in value else []


def parse_env_text(text: str, min_length: int) -> List[KnownSecret]:
    found = []
    for name, raw in _env_entries(text):
        value = _unquote(raw)
        for line in _key_lines(value):
            if is_secret_value(name, line, min_length):
                found.append(KnownSecret(line, name, is_weak(line)))
        # The password inside a URL is a secret of its own, judged the same way
        # (a local `postgres:password@localhost` must not hide the word "password").
        password = URL_PASSWORD.match(value)
        if password and is_secret_value("PASSWORD", password.group(1), min_length):
            found.append(KnownSecret(password.group(1), name, is_weak(password.group(1))))
        if is_secret_value(name, value, min_length):
            found.append(KnownSecret(value, name, is_weak(value)))
    return found


def encoded_variants(value: str) -> List[Tuple[str, str]]:
    """The value plus the encodings it commonly appears in, each with a kind suffix."""
    raw = value.encode("utf-8", "surrogatepass")
    variants = [(value, "")]
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        variants += [(value.lower(), ""), (value.upper(), "")]
    for form in ("NFC", "NFD"):
        normal = unicodedata.normalize(form, value)
        if normal != value:
            variants.append((normal, ""))
    b64 = base64.b64encode(raw).decode("ascii")
    for encoded in {b64, b64.rstrip("="), base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")}:
        variants.append((encoded, ":base64"))
    escaped = json.dumps(value, ensure_ascii=False)[1:-1]
    for encoded, suffix in (
        (quote(value, safe=""), ":urlencoded"),
        (escaped, ":json-escaped"),
        (json.dumps(value)[1:-1], ":json-escaped"),
        (escaped.replace("/", "\\/"), ":json-escaped"),
    ):
        if encoded != value:
            variants.append((encoded, suffix))
    return variants


@dataclass(frozen=True)
class KnownLoad:
    secrets: List[KnownSecret]
    sources: List[str]
    # Files that matched but couldn't be used: their secrets are NOT masked by
    # exact match, so `blindfold doctor` reports them.
    problems: List[Tuple[str, str]]


def _read(path: str, max_bytes: int) -> Tuple[Optional[str], Optional[str]]:
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None, f"larger than {max_bytes} bytes ({size})"
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(), None
    except OSError as error:
        return None, error.strerror or type(error).__name__


def expand_sources(patterns: Iterable[str]) -> List[str]:
    paths = set()
    for pattern in patterns:
        for path in glob.glob(os.path.expanduser(pattern)):
            if os.path.isfile(path):
                paths.add(os.path.realpath(path))
    return sorted(paths)


def load_known_secrets(
    patterns: Iterable[str],
    environ: Optional[Dict[str, str]] = None,
    min_length: int = 8,
    max_file_bytes: int = 4 * 1024 * 1024,
) -> KnownLoad:
    found: Dict[str, KnownSecret] = {}
    problems: List[Tuple[str, str]] = []
    sources = expand_sources(patterns)
    for path in sources:
        text, problem = _read(path, max_file_bytes)
        if problem is not None:
            problems.append((path, problem))
            continue
        for secret in parse_env_text(text or "", min_length):
            found.setdefault(secret.value, secret)
    for name, value in (environ or {}).items():
        if name not in SHELL_STATE and is_secret_name(name, strong=True) and is_secret_value(name, value, min_length):
            found.setdefault(value, KnownSecret(value, name, is_weak(value)))
    return KnownLoad(list(found.values()), sources, problems)
