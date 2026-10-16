"""Walking an agent's JSON values without changing their shape."""

import base64
import binascii
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .mask import Finding, Masker

# Image payloads: masking base64 can only corrupt the image. A string under one
# of these keys is skipped only if it is base64 that decodes to binary (an
# image, a PDF). Base64 that decodes to text (an encoded .env) and anything else
# there (a presigned URL, document text) is masked like any other string.
SKIP_KEYS = frozenset({"base64", "image", "imageData", "data_uri"})
_BLOB = re.compile(r"^(?:data:[^,\s]{0,100},)?([A-Za-z0-9+/=_\s-]{64,})$")


def is_binary_blob(value: str) -> bool:
    match = _BLOB.match(value)
    if not match:
        return False
    sample = re.sub(r"\s", "", match.group(1))[:4096]
    sample = sample[: len(sample) - len(sample) % 4]
    try:
        decoded = base64.b64decode(sample.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        decoded.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return b"\x00" in decoded
# MCP media blocks carry their payload under `data`.
_MEDIA_TYPES = frozenset({"image", "audio", "document"})
# Schema keys look like identifiers; anything else may itself be a value.
_SCHEMA_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")

# json.loads/dumps recurse; give them room for any realistic payload. The walk
# below is iterative, so it has no depth limit of its own.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))


def deep_map(value: Any, fn: Callable[[str], str], map_keys: bool = True) -> Any:
    """Apply fn to every string leaf, keeping the structure and every non-string value.

    Keys go through fn too when map_keys is set: structured MCP results can be
    keyed by a token, while a tool's own schema keys never look like secrets and
    pass unchanged. Withholding sets map_keys=False, since replacing schema keys
    would break the shape the agent requires. Iterative, so no nesting depth can
    make it fail (a failure here would leave the output unmasked).
    """
    root: List[Any] = [None]
    stack: List[Tuple[Any, Any, Any, Optional[str], bool]] = [(value, root, 0, None, False)]
    while stack:
        source, target, slot, key, in_media = stack.pop()
        if isinstance(source, str) and (key in SKIP_KEYS or (in_media and key == "data")) and is_binary_blob(source):
            target[slot] = source
        elif isinstance(source, str):
            target[slot] = fn(source)
        elif isinstance(source, list):
            copy: List[Any] = [None] * len(source)
            target[slot] = copy
            stack.extend((item, copy, index, None, False) for index, item in enumerate(source))
        elif isinstance(source, dict):
            mapping: Dict[Any, Any] = {}
            target[slot] = mapping
            media = source.get("type") in _MEDIA_TYPES
            for k, v in source.items():
                new_key = fn(k) if map_keys and isinstance(k, str) else k
                mapping[new_key] = None
                stack.append((v, mapping, new_key, k if isinstance(k, str) else None, media))
        else:
            target[slot] = source
    return root[0]


def strings(value: Any) -> List[str]:
    """Every string in value, keys included."""
    found: List[str] = []
    deep_map(value, lambda s: found.append(s) or s)
    return found


def mask_value(masker: Masker, value: Any) -> Tuple[Any, List[Finding]]:
    findings: List[Finding] = []

    def mask_string(text: str) -> str:
        masked, found = masker.mask(text)
        findings.extend(found)
        return masked

    return deep_map(value, mask_string), findings


def withhold(value: Any, text: str) -> Any:
    """Every string replaced by text. Schema-like keys are kept so the shape stays
    valid; any other key may itself hold a value, so it is replaced too."""
    withheld = deep_map(value, lambda _s: text, map_keys=False)
    return _rekey(withheld)


def _rekey(value: Any) -> Any:
    root: List[Any] = [None]
    stack: List[Tuple[Any, Any, Any]] = [(value, root, 0)]
    while stack:
        source, target, slot = stack.pop()
        if isinstance(source, list):
            copy: List[Any] = [None] * len(source)
            target[slot] = copy
            stack.extend((item, copy, index) for index, item in enumerate(source))
        elif isinstance(source, dict):
            mapping: Dict[Any, Any] = {}
            target[slot] = mapping
            for index, (k, v) in enumerate(source.items()):
                new_key = k if not isinstance(k, str) or _SCHEMA_KEY.match(k) else f"<blindfold:withheld-key-{index}>"
                mapping[new_key] = None
                stack.append((v, mapping, new_key))
        else:
            target[slot] = source
    return root[0]
