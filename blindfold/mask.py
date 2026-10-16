"""The masking engine: text in, masked text plus findings out."""

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Match, Optional, Pattern, Tuple

from .known import KnownSecret, encoded_variants
from .rules import HIGH_ENTROPY_TOKEN, RULES, Rule, is_code_line, is_placeholder, is_secret_name, is_secretish, looks_random, starts_token

# The exact shape of a placeholder blindfold emits. The write guard and idempotence
# rely on it, so change it only with both.
PLACEHOLDER_RE = re.compile(r"<blindfold kind=[A-Za-z0-9:_.-]{1,80} len=\d{1,9} id=[0-9a-f]{6}>")
# ANSI escapes can split a token so no pattern sees it whole; the model gains
# nothing from them, so they go wherever masking changes a string.
ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x9b[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|.\x08"
)

# While a string is being masked, each hidden value becomes a sentinel token made
# of private-use characters, rendered as a placeholder only at the end. Only
# those tokens are protected from later passes: text that merely looks like a
# placeholder gets no protection, so a forged `<blindfold kind=TOKEN …>` can't
# smuggle a value past the mask. Sentinel characters already in the input are
# neutralised first so input can't forge a token either.
_OPEN, _CLOSE = "\ue000", "\ue001"
_SENTINEL_RE = re.compile(_OPEN + r"(\d+)" + _CLOSE)


@dataclass(frozen=True)
class Finding:
    kind: str
    length: int
    fingerprint: str
    # From a word-like known value: masked, but not a reason to refuse or alarm.
    weak: bool = False

# The trie that matches known values recurses per character; an encoded
# variant past this is skipped (a value that long is key material, which the
# private-key rules cover).
MAX_VARIANT_LENGTH = 4096


class Masker:
    def __init__(
        self,
        known: Iterable[KnownSecret] = (),
        key: bytes = b"",
        entropy: bool = True,
        min_entropy: float = 4.2,
        allow: Iterable[str] = (),
        allow_ids: Iterable[str] = (),
        disabled_rules: Iterable[str] = (),
    ):
        self._key = key
        self._disabled = set(disabled_rules)
        self._entropy = entropy and "high-entropy" not in self._disabled
        self._min_entropy = min_entropy
        self._allow = set(allow)
        self._allow_ids = {i.lower() for i in allow_ids}
        self._rules = [rule for rule in RULES if rule.kind not in self._disabled]
        names: Dict[str, str] = {}
        weak: Dict[str, str] = {}
        for secret in known:
            if secret.value in self._allow:
                continue
            for variant, suffix in encoded_variants(secret.value):
                if len(variant) <= MAX_VARIANT_LENGTH:
                    (weak if secret.weak else names).setdefault(variant, secret.name + suffix)
        self._known_names = {**weak, **names}
        self._weak_values = set(weak) - set(names)
        self._known_re: Optional[Pattern[str]] = re.compile(trie_pattern(names)) if names else None
        # Word-like values only as whole words, so one doesn't hide part of a longer word.
        self._weak_re: Optional[Pattern[str]] = (
            re.compile(r"(?<![A-Za-z0-9])(?:" + trie_pattern(weak) + r")(?![A-Za-z0-9])") if weak else None
        )

    @property
    def known_count(self) -> int:
        return len(self._known_names)

    def fingerprint(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:6]

    def placeholder(self, kind: str, value: str) -> str:
        safe_kind = re.sub(r"[^A-Za-z0-9:_.-]", "_", kind)[:80]
        return f"<blindfold kind={safe_kind} len={len(value)} id={self.fingerprint(value)}>"

    def mask(self, text: str) -> Tuple[str, List[Finding]]:
        return self._mask(text, keep_existing=True)

    def _kind_is_clean(self, placeholder: str) -> bool:
        """An existing placeholder is kept as-is only if its kind hides nothing.

        That keeps masking idempotent while a forged placeholder whose kind
        carries a token (`<blindfold kind=ghp_… len=1 id=000000>`) is masked.
        """
        kind = placeholder.split("kind=", 1)[1].split(" ", 1)[0]
        return not self._mask(kind, keep_existing=False)[1]

    def _mask(self, text: str, keep_existing: bool) -> Tuple[str, List[Finding]]:
        if not text:
            return text, []
        findings: List[Finding] = []
        placeholders: List[str] = []
        original = text
        if "\x1b" in text:
            text = ANSI_RE.sub("", text)
        if _OPEN in text or _CLOSE in text:
            text = text.replace(_OPEN, "\ufffd").replace(_CLOSE, "\ufffd")

        def keep(match: Match[str]) -> str:
            if not self._kind_is_clean(match.group(0)):
                return match.group(0)
            placeholders.append(match.group(0))
            return f"{_OPEN}{len(placeholders) - 1}{_CLOSE}"

        if keep_existing and "<blindfold kind=" in text:
            text = PLACEHOLDER_RE.sub(keep, text)

        def hide(kind: str, value: str, weak: bool = False) -> Optional[str]:
            fingerprint = self.fingerprint(value)
            # Known secrets can't be allowed by id: an id is all an agent sees.
            if fingerprint in self._allow_ids and not kind.startswith("env:"):
                return None
            findings.append(Finding(kind, len(value), fingerprint, weak))
            placeholders.append(self.placeholder(kind, value))
            return f"{_OPEN}{len(placeholders) - 1}{_CLOSE}"

        if self._known_re is not None:
            text = _replace(self._known_re, text, 0, lambda m: hide("env:" + self._known_names[m.group(0)], m.group(0)))
        if self._weak_re is not None:
            text = _replace(self._weak_re, text, 0, lambda m: hide("env:" + self._known_names[m.group(0)], m.group(0), weak=True))

        for rule in self._rules:
            text = _replace(rule.pattern, text, rule.group, lambda m, r=rule: self._rule_hit(r, m, hide))

        if self._entropy:
            text = _replace(HIGH_ENTROPY_TOKEN, text, 0, self._entropy_hit(hide))

        if not findings:
            return original, []
        return _SENTINEL_RE.sub(lambda m: placeholders[int(m.group(1))], text), findings

    def _entropy_hit(self, hide) -> Callable[[Match[str]], Optional[str]]:
        def hit(match: Match[str]) -> Optional[str]:
            value = match.group(0)
            if value in self._allow or not looks_random(value, self._min_entropy):
                return None
            # A slashed token right after `.`, `/` or `:` is a URL or file path
            # (owasp.org/Top10/A03_2021-Injection); one after `#` is an anchor.
            before = match.string[match.start() - 1 : match.start()]
            if ("/" in value and before in (".", "/", ":")) or before == "#":
                return None
            return hide("high-entropy", value)

        return hit

    def _rule_hit(self, rule: Rule, match: Match[str], hide) -> Optional[str]:
        value = match.group(rule.group)
        if value in self._allow or (rule.bounded and not starts_token(match.string, match.start())):
            return None
        strong = rule.context == "strong"
        if rule.name_group is not None and not is_secret_name(match.group(rule.name_group), strong=strong):
            return None
        if rule.name_group is None and not strong:
            # A shape rule. Its captured value can still be a template or a
            # stand-in: ?token=${resetToken}, postgres://postgres:password@host.
            if rule.group and is_placeholder(value):
                return None
            return hide(rule.kind, value)
        quote = value[0] if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0] else ""
        inner = value[1:-1] if quote else value
        context = "strong" if strong else "quoted" if quote or _whole_line(match, rule.group) else "bare"
        if context == "bare" and _in_code(match, rule.group):
            return None
        if inner in self._allow or not is_secretish(inner, context):
            return None
        masked = hide(rule.kind, inner)
        return None if masked is None else f"{quote}{masked}{quote}"


def trie_pattern(words: Iterable[str]) -> str:
    """One regex matching any of words, preferring the longest.

    A flat alternation of hundreds of literals makes the engine try every one at
    every position; factoring shared prefixes into a trie lets it rule most out
    at the first character. Greedy optional tails keep longest-match-wins.
    """
    trie: Dict[str, Any] = {}
    for word in words:
        node = trie
        for char in word:
            node = node.setdefault(char, {})
        node[""] = {}

    def build(node: Dict[str, Any]) -> str:
        branches = [re.escape(char) + build(child) for char, child in sorted(node.items()) if char]
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        return f"(?:{body})?" if "" in node else body

    return build(trie)


def _line_of(match: Match[str]) -> Tuple[int, int]:
    text = match.string
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    return start, end if end >= 0 else len(text)


def _whole_line(match: Match[str], group: int) -> bool:
    """A `name: value` or `name=value` that is the whole line (YAML, .properties,
    a compose `- NAME=value` item): config, not code, so a bare value counts."""
    start, end = _line_of(match)
    text = match.string
    before = text[start : match.start()].strip(" \t-+")
    after = text[match.end(group) : end].strip()
    return not before and (not after or after.startswith("#"))


def _in_code(match: Match[str], group: int) -> bool:
    """Whether an unquoted value sits in code: a JS/TS property ends in `,`, and
    an expression line carries operators or keywords. A `;` is not a sign of
    code: it separates connection-string fields (Password=x;Server=y;)."""
    start, end = _line_of(match)
    text = match.string
    after = text[match.end(group) : match.end(group) + 1]
    return after == "," or is_code_line(text[start:end])


def _replace(pattern: Pattern[str], text: str, group: int, replace: Callable[[Match[str]], Optional[str]]) -> str:
    """Replace `group` of each match that `replace` maps to text, never across a value already hidden."""
    protected = [m.span() for m in _SENTINEL_RE.finditer(text)] if _OPEN in text else []
    pieces: List[str] = []
    last = 0
    for match in pattern.finditer(text):
        start, end = match.span(group)
        if start < 0 or start < last:
            continue
        # A match touching a hidden value is left alone: the value stays hidden,
        # and re-hiding the span would lose the more precise earlier label.
        if any(s < end and start < e for s, e in protected):
            continue
        replacement = replace(match)
        if replacement is None:
            continue
        pieces.append(text[last:start])
        pieces.append(replacement)
        last = end
    if not pieces:
        return text
    pieces.append(text[last:])
    return "".join(pieces)
