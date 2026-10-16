"""User configuration: ~/.config/blindfold/config.json (or $BLINDFOLD_CONFIG)."""

import json
import os
import secrets as _random
import time
from dataclasses import dataclass, field, fields
from typing import List

CONFIG_DIR = os.path.expanduser(os.environ.get("BLINDFOLD_HOME", "~/.config/blindfold"))
CONFIG_PATH = os.environ.get("BLINDFOLD_CONFIG", os.path.join(CONFIG_DIR, "config.json"))
KEY_PATH = os.path.join(CONFIG_DIR, "fingerprint.key")

# Real secret files only. Committed templates (.env.sample, .env.example,
# .env.test) hold fake values that also appear in test code; treating them as
# known secrets would mask fixtures and make the write guard refuse test edits.
_ENV_NAMES = [".env", ".env.local", ".env.*.local", ".env.production", ".env.staging", ".env.development"]
_ENV_DIRS = ["~", "~/projects/*", "~/projects/*/*", "~/projects/*/worktrees/*/*"]
DEFAULT_SOURCES = ["~/.config/*/*.env", "~/.config/*/.env"] + [f"{d}/{n}" for d in _ENV_DIRS for n in _ENV_NAMES]


# macOS Keychain reads that print the password, and 1Password reads.
DEFAULT_BLOCKED_COMMANDS = [
    r"\bsecurity\s+(?:find-(?:generic|internet)-password\b[^|;&]*\s-[a-zA-Z]*[wg]|dump-keychain)",
    r"\bop\s+(?:read|inject)\b",
    r"\bop\s+item\s+get\b[^|;&]*(?:--reveal|--fields|--format)",
    r"\bop\s+document\s+get\b",
]


@dataclass
class Config:
    # Files whose values are masked by exact match (dotenv-style KEY=value):
    # the defaults plus any extras.
    extra_known_secret_files: List[str] = field(default_factory=list)
    use_default_known_secret_files: bool = True
    # Shortest known value that is masked by exact match; shorter ones would hit ordinary text.
    min_known_length: int = 8
    # Mask long random tokens no rule recognises.
    entropy: bool = True
    min_entropy: float = 4.2
    # Values never masked (exact strings), e.g. a public client id that looks random.
    allow: List[str] = field(default_factory=list)
    # Placeholder ids never masked: lets a false positive be allowed without
    # anyone typing its value. Ids of known secrets (env:*) are never honoured.
    allow_ids: List[str] = field(default_factory=list)
    # Rule kinds turned off, e.g. "high-entropy" or "named-secret".
    disabled_rules: List[str] = field(default_factory=list)
    # Refuse a call whose input carries a blindfold placeholder (it would replace or
    # corrupt the real value) or a known secret's value.
    guard_placeholders: bool = True
    guard_known_values: bool = True
    # Commands whose whole output is a bare secret, which no rule can recognise:
    # refused outright (regexes, matched against Bash commands).
    blocked_commands: List[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_COMMANDS))
    # Make Claude Code Bash commands exit 0 (reporting the real code) so their
    # output can be masked; Claude can't replace a failed call's output.
    wrap_claude_bash: bool = True

    @property
    def known_secret_files(self) -> List[str]:
        defaults = DEFAULT_SOURCES if self.use_default_known_secret_files else []
        return [*defaults, *self.extra_known_secret_files]


def _check_types(raw: dict) -> None:
    """Reject a wrongly typed value here, where it takes the safe fallback.

    Unchecked, `"entropy": "false"` would be truthy, a string of files would be
    globbed one character at a time, and a bad list would crash every call.
    """
    defaults = Config()
    for key, value in raw.items():
        expected = getattr(defaults, key)
        if isinstance(expected, bool):
            ok = isinstance(value, bool)
        elif isinstance(expected, (int, float)):
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        else:
            ok = isinstance(value, list) and all(isinstance(item, str) for item in value)
        if not ok:
            raise ValueError(f"{key} must be {'a list of strings' if isinstance(expected, list) else type(expected).__name__}")


def load_config() -> Config:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return Config()
    if not isinstance(raw, dict):
        raise ValueError(f"{CONFIG_PATH} must hold a JSON object")
    known = {f.name for f in fields(Config)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ValueError(f"Unknown blindfold config keys in {CONFIG_PATH}: {', '.join(unknown)}")
    _check_types(raw)
    return Config(**raw)


def fingerprint_key() -> str:
    """A per-machine random key for placeholder ids, as 64 hex characters.

    Ids let the agent see that two placeholders hide the same value without
    being able to confirm a guess offline: an unkeyed hash of a weak password
    could be brute-forced from the id. Hex text (not raw bytes) so the key is
    itself masked by exact match if anything ever prints the file.
    """
    def valid(text: str) -> bool:
        return len(text) == 64 and all(c in "0123456789abcdef" for c in text)

    try:
        with open(KEY_PATH, encoding="ascii", errors="replace") as handle:
            key = handle.read().strip()
        if valid(key):
            return key
        raise ValueError(f"{KEY_PATH} is not a blindfold key; move it aside and blindfold makes a new one")
    except FileNotFoundError:
        pass
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    key = _random.token_hex(32)
    try:
        descriptor = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another hook process is creating it; use theirs once it's written.
        for _ in range(100):
            with open(KEY_PATH, encoding="ascii", errors="replace") as handle:
                existing = handle.read().strip()
            if valid(existing):
                return existing
            time.sleep(0.01)
        raise
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(key + "\n")
    return key
