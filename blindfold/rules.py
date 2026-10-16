"""Pattern rules for secrets blindfold has not been told about.

The policy is to prefer false positives: a masked non-secret costs a little
friction, a missed secret costs a rotation. The exception is code, where
masking identifiers would make files uneditable, so in code only literals count.

Vendor prefixes follow gitleaks (MIT) where it has a precise rule. Names are
judged segment by segment (after cadence-hooks' policy). No pattern nests
quantifiers, so matching stays linear on long minified lines.
"""

import math
import re
from dataclasses import dataclass
from typing import Optional, Pattern


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: Pattern[str]
    group: int = 0
    # When set, the match counts only if this group is a secret name.
    name_group: Optional[int] = None
    # How strongly the shape vouches for the value: "strong" (a NAME=value
    # line, a --password flag), else judged by quoting and surroundings.
    context: str = "auto"
    # The match must start a token (checked after matching: a lookbehind here
    # would cost every vendor pattern its fast literal-prefix scan).
    bounded: bool = False


def _rule(
    kind: str, regex: str, group: int = 0, flags: int = 0, name_group: Optional[int] = None, context: str = "auto", bounded: bool = False
) -> Rule:
    return Rule(kind, re.compile(regex, flags), group, name_group, context, bounded)


def starts_token(text: str, index: int) -> bool:
    """Not inside a word, but a literal \\n or \\t in JSON text counts as a break."""
    return index == 0 or not text[index - 1].isalnum() or text[index - 2 : index] in ("\\n", "\\t", "\\r")


# --- names -----------------------------------------------------------------

_SEGMENT_SPLIT = re.compile(r"[_./\-\s]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
# A segment containing one of these holds a secret: PGPASSWORD, ADMINPASSWORD, clientsecret.
_STRONG_PARTS = ("password", "passwd", "secret", "passphrase")
_STRONG = {
    "pwd", "token", "credential", "credentials", "dsn", "salt", "apikey", "privatekey", "accesskey",
    "authtoken", "accesstoken", "refreshtoken", "bearer", "cookie", "pat", "pin", "otp",
}
_PAIRS = {
    ("api", "key"), ("private", "key"), ("access", "key"), ("secret", "key"), ("signing", "key"),
    ("encryption", "key"), ("session", "key"), ("master", "key"), ("license", "key"),
    ("auth", "key"), ("client", "secret"), ("auth", "token"), ("service", "key"),
    ("account", "key"), ("app", "key"), ("webhook", "secret"), ("shared", "secret"),
}
# A trailing short form that names a secret on a NAME=value line (SMTP_PASS,
# DB_PW, MAILGUN_KEY) but is too common in code to count there.
_STRONG_CONTEXT_TAILS = {"pass", "pw", "key", "keys"}
# The last segment is the head noun: TOKEN_URL is a url, API_KEY_ID an id.
_NOT_A_VALUE_HEAD = {
    "id", "ids", "url", "uri", "endpoint", "path", "file", "filename", "dir", "name", "type",
    "length", "len", "size", "count", "limit", "max", "min", "num", "total", "usage", "ttl",
    "expiry", "expires", "expire", "expiration", "header", "prefix", "suffix", "field",
    "column", "label", "hint", "policy", "mode", "version", "enabled", "required", "regex",
    "pattern", "format", "provider", "kind", "exists", "configured", "placeholder", "fingerprint",
    "location", "env", "var", "tokens", "tokenizer", "store", "manager", "rotation", "rotated",
    "timeout", "ms", "seconds", "secs", "minutes", "hours", "days", "interval", "delay", "retries",
    "attempts", "spec", "schema", "status", "state", "error", "errors", "message", "title", "copy",
    "text", "description", "completed", "reset", "changed", "updated", "at", "set", "visible",
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "rb", "go", "rs", "sh", "json", "yaml", "yml", "md", "toml",
}
# Anywhere in the name, these mean the value is meant to be seen.
_PUBLIC = {"public", "publishable", "example", "sample"}


def name_segments(name: str):
    return [s.lower() for s in _SEGMENT_SPLIT.split(name.strip("\"'`")) if s]


def is_secret_name(name: str, strong: bool = False) -> bool:
    segments = name_segments(name)
    if not segments or segments[-1] in _NOT_A_VALUE_HEAD or _PUBLIC.intersection(segments):
        return False
    if any(part in segment for segment in segments for part in _STRONG_PARTS):
        return True
    if any(s in _STRONG for s in segments) or any(pair in _PAIRS for pair in zip(segments, segments[1:])):
        return True
    return strong and segments[-1] in _STRONG_CONTEXT_TAILS


# --- values ----------------------------------------------------------------

PLACEHOLDER_VALUE = re.compile(
    r"""^(?:
        |true|false|null|none|nil|undefined|yes|no|on|off|empty|unset|required|optional
        |x+|\*+|\.+|-+|\#+|changeme|change[_-]?me|example|sample|dummy|test|testing|redacted|secret|password
        |values?|val|placeholder|foo|bar|baz|foobar
        |your[_-].*|<.*>|\[.*\]|\$\{.*\}|\$\(.*\)|\$[A-Za-z_][A-Za-z0-9_]*|%\(.*\)s|%s|\{\{.*\}\}|\{.*\}
        |process\.env\..*|import\.meta\.env\..*|os\.environ.*|env\(.*\)|getenv\(.*\)|config\..*
        |string|str|number|int|integer|boolean|bool|any|object|bytes|buffer|secretstr
        |.*(?:[_-]x{3,}|^x{3,}|\*{3,}|\.{3}|…).*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
_CALL = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*\(.*\)$")
_ATTRIBUTE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
# Code: a call, type, arrow function, generic, object or array literal.
_CODE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*\(|^[(\[{]|=>|<|\bawait\b|\bnew [A-Z]|\btypeof\b")
_SEQUENCE = re.compile(r"^[(\[]\s*(?:[\"'(\[]|[A-Za-z_]\w*\s*,)")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$")
# A slug, word or path: letters and separators only, no digits.
_SLUG = re.compile(r"^/?[A-Za-z]+(?:[-_./:][A-Za-z]+)*/?$")
# A version or range (^0.7.1, ~2.3, >=1.0.0) or a plain number.
_VERSION = re.compile(r"^[~^>=<v]*\d+(?:\.[0-9A-Za-z*x-]+)+$|^[0-9][0-9_.,]*$")
# Prose: words and ordinary punctuation, at least one space, no digits.
_PROSE = re.compile(r"^[A-Za-z][A-Za-z'’.,!?:;()&/-]*(?:\s+[A-Za-z'’.,!?:;()&/-]+)+$")
# A shell command: several words with a flag, path or assignment.
_COMMAND = re.compile(r"^\S+(?:\s+\S+){2,}$")
_COMMAND_MARKER = re.compile(r"(?:^|\s)(?:-{1,2}[A-Za-z]|\./|[A-Z_]+=)|\.(?:ts|js|mjs|py|sh)\b")
# A line that is code, where an unquoted value is an expression, not a literal.
_CODE_LINE = re.compile(r"\b(?:const|let|var|return|function|await|typeof|instanceof)\b|=>|===|!==|&&|\|\||\?\.|\?\?")


def is_placeholder(value: str) -> bool:
    """Whether a value found next to a secret-looking name is clearly not a secret."""
    stripped = value.strip()
    # Prose punctuation after a stand-in word ("--password value, …") isn't part of it.
    return len(stripped) < 4 or bool(PLACEHOLDER_VALUE.match(stripped)) or bool(PLACEHOLDER_VALUE.match(stripped.rstrip(".,;:!?")))


def is_code_line(line: str) -> bool:
    return bool(_CODE_LINE.search(line))


def _random_identifier(value: str) -> bool:
    """An identifier-shaped value that is really a random token.

    Random base62 of 16+ characters has several digits and capitals and no
    dots; code identifiers (session2.token, oauth2Client) don't.
    """
    return (
        len(value) >= 16
        and "." not in value
        and sum(c.isdigit() for c in value) >= 2
        and sum(c.isupper() for c in value) >= 2
        and any(c.islower() for c in value)
        and shannon_entropy(value) >= 3.5
    )


def is_secretish(value: str, context: str) -> bool:
    """Whether a value next to a secret name should be masked.

    - "strong" (a NAME=value line, a --password flag, a name/value pair):
      anything but a placeholder or a function call, numbers included.
    - "quoted" (a string literal, or a whole `name: value` line in YAML or
      .properties): not a plain slug, word, prose or version.
    - "bare" (an unquoted value inside a larger line): must look like a
      credential, since in code a bare value is an identifier or expression.
    """
    stripped = value.strip()
    if is_placeholder(stripped):
        return False
    if context == "strong":
        # A call, an attribute reference (settings.DB_PASSWORD) or a list or
        # tuple literal (RESULT_KEYS = ("a", "b")) is code. A secret inside a
        # literal is still caught by the vendor and entropy rules.
        return not (_CALL.match(stripped) or _ATTRIBUTE.match(stripped) or _SEQUENCE.match(stripped))
    if _CODE.search(stripped) or _VERSION.match(stripped):
        return False
    if _COMMAND.match(stripped) and _COMMAND_MARKER.search(stripped):
        return False
    if context == "quoted":
        return not (_SLUG.match(stripped) or _PROSE.match(stripped))
    if _IDENTIFIER.match(stripped):
        return _random_identifier(stripped)
    return not _SLUG.match(stripped) and bool(re.search(r"[0-9!@#%^&*+=~?]", stripped))


# --- rules -----------------------------------------------------------------

_NAME = r"([A-Za-z_][A-Za-z0-9_.-]{0,63})"
_QUOTED = r"\"(?:[^\"\\\n]|\\.){1,2048}\"|'[^'\n]{1,2048}'"
_QUOTED_OR_BARE = r"(" + _QUOTED + r"|[^\s\"',;`]{1,2048})"
# A NAME=value line's value runs to the end of the line, less a ` # comment`.
_LINE_VALUE = r"(" + _QUOTED + r"|[^\s\"'][^\n]{0,2047}?)(?=[ \t]+#|[ \t\r]*$)"
_END = r"(?![A-Za-z0-9_])"
# Between the name and value fields of a pair: separators and up to three short fields.
_BETWEEN = r"(?:[ \t]*,?[ \t]*\r?\n?[ \t]*-?[ \t]*[\"'][A-Za-z]{1,20}[\"'][ \t]*:[ \t]*(?:\"[^\"\n]{0,200}\"|[0-9A-Za-z]{1,20})){0,3}[ \t]*,?[ \t]*\r?\n?[ \t]*-?[ \t]*"
# Lines as tools print them: diff (+/-), `cat -n` (N<tab>), grep (file:N:), a YAML list item.
_LINE_PREFIX = r"^[ \t]*(?:[-+][ \t]*|\d+\t|[^\s:=]{1,200}:(?:\d+:)?)?(?:export[ \t]+)?"


def _vendor(kind: str, body: str, flags: int = 0) -> Rule:
    return _rule(kind, body + _END, flags=flags, bounded=True)


RULES = [
    # A private key, whole or cut short (head, a Read with a limit).
    _rule(
        "private-key",
        r"-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{1,16384}?-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----|(?:(?:\\n|\s){1,4}[A-Za-z0-9+/=]{16,}){1,400})",
    ),
    _rule("private-key-base64", r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{20,}", bounded=True),
    _rule("putty-private-key", r"PuTTY-User-Key-File-\d: [\s\S]{1,8192}?Private-MAC: [0-9a-f]+"),
    _vendor("age-secret-key", r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
    _vendor("aws-access-key", r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}"),
    _vendor("github-token", r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})"),
    _vendor("gitlab-token", r"gl(?:pat|ptt|dt|rt|cbt|imt|oas|soat|ft|agent)-[A-Za-z0-9_-]{20,}"),
    _vendor("slack-token", r"xox[abposre]-(?:[0-9]+-)?[A-Za-z0-9-]{10,250}"),
    _rule("slack-webhook", r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,200}"),
    _rule("discord-webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,80}"),
    _vendor("telegram-bot-token", r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    _vendor("stripe-key", r"(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{16,255}"),
    _vendor("stripe-webhook-secret", r"whsec_[A-Za-z0-9+/=]{20,}"),
    _vendor("anthropic-key", r"sk-ant-(?:api|admin|sid)[0-9]{2}-[A-Za-z0-9_-]{20,}"),
    _vendor("openai-key", r"sk-(?:proj-|svcacct-|admin-|None-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
    _vendor("openai-key", r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"),
    _vendor("openrouter-key", r"sk-or-v1-[a-f0-9]{64}"),
    _vendor("google-api-key", r"AIza[0-9A-Za-z_-]{35}"),
    _vendor("google-oauth-secret", r"GOCSPX-[A-Za-z0-9_-]{20,}"),
    _vendor("sendgrid-key", r"SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}"),
    _vendor("mailgun-key", r"key-[a-f0-9]{32}"),
    _vendor("npm-token", r"npm_[A-Za-z0-9]{36}"),
    _vendor("pypi-token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    _vendor("sentry-token", r"sntry[su]_[A-Za-z0-9_=+/]{30,}"),
    _vendor("resend-key", r"re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}"),
    _vendor("linear-key", r"lin_(?:api|oauth)_[A-Za-z0-9]{30,}"),
    _vendor("huggingface-token", r"hf_[A-Za-z0-9]{30,}"),
    _vendor("shopify-token", r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"),
    _vendor("doppler-token", r"dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"),
    _vendor("vault-token", r"hv[sb]\.[A-Za-z0-9_-]{24,}"),
    _vendor("heroku-token", r"HRKU-AA[0-9A-Za-z_-]{58}"),
    _vendor("digitalocean-token", r"do[opr]_v1_[a-f0-9]{64}"),
    _vendor("databricks-token", r"dapi[a-f0-9]{32}(?:-\d)?"),
    _vendor("notion-token", r"ntn_[0-9]{11}[A-Za-z0-9]{35}"),
    _vendor("planetscale-token", r"pscale_(?:tkn|oauth|pw)_[A-Za-z0-9=._-]{32,64}"),
    _vendor("postman-key", r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}"),
    _vendor("grafana-token", r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}"),
    _vendor("perplexity-key", r"pplx-[A-Za-z0-9]{48}"),
    _vendor("langsmith-key", r"lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}"),
    _rule("onepassword-service-token", r"ops_eyJ[A-Za-z0-9+/=_-]{100,}", bounded=True),
    _rule("password-hash", r"\$(?:2[abxy]|argon2(?:id|i|d))\$[^\s\"']{20,}"),
    _rule("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", bounded=True),
    _rule("k8s-client-key", r"client-key-data:\s*([A-Za-z0-9+/=]{40,})", 1),
    _rule("docker-auth", r"\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{12,})\"", 1),
    # scheme://user:password@host (user may be empty: redis://:pw@host).
    _rule("url-password", r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"<>]{0,128}:([^\s@/'\"<>]{3,256})@", 1, re.IGNORECASE),
    _rule("sentry-dsn-key", r"https://([0-9a-f]{32})(?::[0-9a-f]{32})?@[a-z0-9.-]*\bsentry\.io\b", 1),
    _rule(
        "auth-header",
        r"\b(?:proxy-)?authorization\s*[:=]\s*[\"']?(?:bearer|basic|token|bot|digest)\s+([A-Za-z0-9._~+/=:-]{8,})",
        1,
        re.IGNORECASE,
    ),
    _rule("api-key-header", r"\bx-(?:api|auth|access)-(?:key|token)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{8,})", 1, re.IGNORECASE),
    # Every cookie value in a Cookie or Set-Cookie header (sessions are credentials).
    _rule("cookie-header", r"(?im)^[ \t]*(?:<\s*|>\s*)?(?:set-)?cookie:[ \t]*([^\n]{8,})", 1),
    # Requires a digit, so prose ("a bearer token-like value") is left alone.
    _rule("bearer-token", r"\bbearer\s+((?=[A-Za-z0-9._~+/-]{0,200}[0-9])[A-Za-z0-9._~+/-]{20,}=*)", 1, re.IGNORECASE),
    _rule(
        "url-secret-param",
        r"[?&](?:access_token|refresh_token|id_token|api_key|apikey|token|secret|password|sig|signature|X-Amz-Signature|X-Amz-Credential)=([^&\s\"'#`]{8,})",
        1,
        re.IGNORECASE,
    ),
    # .netrc (machine h login u password p) and .pgpass (host:port:db:user:password).
    _rule(
        "netrc-password",
        r"(?im)^[ \t]*(?:machine[ \t]+\S+|default)(?:[ \t\r\n]+(?:login|account)[ \t]+\S+)*[ \t\r\n]+password[ \t]+(\S+)",
        1,
        context="strong",
    ),
    _rule("pgpass-password", r"(?m)^[A-Za-z0-9_.*-]+:(?:\d+|\*):[^:\s]+:[^:\s]+:(\S+)$", 1, context="strong"),
    # Kubernetes / ECS / SSM: a secret name and its value under a `value` key,
    # either order, with up to three other short fields between (SSM's "Type").
    _rule(
        "name-value-pair",
        r"(?i)\bname[\"']?[ \t]*:[ \t]*[\"']?([A-Za-z_/][A-Za-z0-9_./-]{0,127})[\"']?" + _BETWEEN
        + r"[\"']?value[\"']?[ \t]*:[ \t]*" + _QUOTED_OR_BARE,
        2,
        name_group=1,
        context="strong",
    ),
    _rule(
        "name-value-pair",
        r"(?i)[\"']value[\"'][ \t]*:[ \t]*(" + _QUOTED + r")" + _BETWEEN
        + r"[\"']name[\"'][ \t]*:[ \t]*[\"']([A-Za-z_/][A-Za-z0-9_./-]{0,127})[\"']",
        1,
        name_group=2,
        context="strong",
    ),
    # A NAME=value line, the strongest signal, as tools print it.
    _rule(
        "env-assignment",
        _LINE_PREFIX + r"([A-Z_][A-Z0-9_.-]{0,63})[ \t]*=[ \t]*" + _LINE_VALUE,
        2,
        re.MULTILINE,
        name_group=1,
        context="strong",
    ),
    # "name": "value" / name: value / name = "value" in code, JSON, YAML, TOML.
    _rule(
        "named-secret",
        r"(?<![A-Za-z0-9_.])[\"']?" + _NAME + r"[\"']?[ \t]*(?::=|=>|:|=)[ \t]*" + _QUOTED_OR_BARE,
        2,
        name_group=1,
    ),
    # --password value, --db-password=value, --api-key value.
    _rule(
        "cli-secret-flag",
        r"--(?:[a-z0-9]+-){0,4}(?:password|passwd|pass|pwd|token|secret|api-key|apikey|access-key|secret-key|client-secret|auth-token)"
        r"(?:=|[ \t]+)(\"[^\"\n]+\"|'[^'\n]+'|[^\s\"'-][^\s\"']{3,})",
        1,
        re.IGNORECASE,
        context="strong",
    ),
]

# Precise enough to block a pasted prompt on: vendor formats and key material,
# not the name- or entropy-based judgements.
PROMPT_BLOCKING_KINDS = frozenset(
    {rule.kind for rule in RULES if rule.bounded}
    | {"private-key", "putty-private-key", "slack-webhook", "discord-webhook", "password-hash"}
)

# --- entropy ---------------------------------------------------------------

# A long random-looking token no rule named. '=' ends a token unless it is
# trailing padding, so `AccountKey=<base64>` is judged by its value alone.
HIGH_ENTROPY_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX_ONLY = re.compile(r"^[0-9a-fA-F-]+$")
_NOT_SECRET_PREFIX = re.compile(r"^(?:sha(?:1|256|384|512)-|h1-|data-|/)", re.IGNORECASE)
# A short label and then 32+ hex is a key (sk_<hex>, fc-<hex>), not a SHA.
_PREFIXED_HEX = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,11}[-_](?:[A-Za-z0-9]{1,8}[-_])?[0-9a-f]{32,}$")


def shannon_entropy(value: str) -> float:
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    size = len(value)
    return -sum(n / size * math.log2(n / size) for n in counts.values()) if size else 0.0


def looks_random(token: str, min_entropy: float) -> bool:
    if _NOT_SECRET_PREFIX.match(token):
        return False
    # Before the pure-hex check: a label like `fc-` is itself made of hex letters.
    if _PREFIXED_HEX.match(token):
        return True
    if _HEX_ONLY.match(token):
        return False
    size = len(token)
    # Base64 has `/` but never `-` or `_`; URL-safe base64 has those but no `/`.
    # Both together is a path or URL (owasp.org/Top10/A04_2021-Insecure_Design).
    if "/" in token and ("-" in token or "_" in token):
        return False
    # Separator-heavy tokens are paths, slugs or identifiers, not keys.
    if token.count("/") / size > 0.08 or (token.count("-") + token.count("_")) / size > 0.15:
        return False
    if not (any(c.isalpha() for c in token) and any(c.isdigit() for c in token)):
        return False
    mixed_case = any(c.islower() for c in token) and any(c.isupper() for c in token)
    # A one-case token in 3+ dash/underscore parts is a slug (heading anchors,
    # package names); prefixed keys like sk-or-v1-<hex> are caught above.
    if not mixed_case and len(re.split(r"[-_]+", token)) >= 3:
        return False
    # A one-case alphabet (36 symbols) has less room for entropy than base62.
    return shannon_entropy(token) >= (min_entropy if mixed_case else min_entropy - 0.4)
