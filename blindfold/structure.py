"""Walking an agent's JSON values without changing their shape."""

import base64
import binascii
import re
import sys
import zlib
from typing import Any, Callable, Dict, List, Optional, Tuple

from .mask import Finding, Masker

# Image payloads: masking base64 can only corrupt the image. A string under one
# of these keys is skipped only if all of it is valid base64 that decodes to an
# image or a PDF (checked by its signature). Anything else there, such as an
# encoded .env, a presigned URL or document text, is masked like any string.
SKIP_KEYS = frozenset({"base64", "image", "imageData", "data_uri"})
_BLOB = re.compile(r"^(?:data:[^,\s]{0,100},)?([A-Za-z0-9+/=_\s-]{64,})$")


# MCP media blocks carry their payload under `data`.
_MEDIA_TYPES = frozenset({"image", "audio", "document"})
# Schema keys look like identifiers; anything else may itself be a value.
_SCHEMA_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
# PNG, JPEG, GIF, WebP (RIFF), PDF.
_MEDIA_SIGNATURES = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"RIFF", b"%PDF-")


def is_binary_blob(value: str) -> bool:
    match = _BLOB.match(value)
    if not match:
        return False
    encoded = re.sub(r"\s", "", match.group(1)).replace("-", "+").replace("_", "/")
    try:
        decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    return decoded.startswith(_MEDIA_SIGNATURES)


# json.loads/dumps recurse; give them room for any realistic payload. The walk
# below is iterative, so it has no depth limit of its own.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))


# Inflated text scanned per blob, so a zip bomb can't stall the hook.
MAX_INFLATED = 4 << 20
_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)


def _png_text_chunks(data: bytes) -> List[bytes]:
    """tEXt/zTXt/iTXt chunk bodies; pixel data (IDAT) is skipped as noise."""
    chunks, at = [], 8
    while at + 8 <= len(data):
        length, kind = int.from_bytes(data[at : at + 4], "big"), data[at + 4 : at + 8]
        if kind in (b"tEXt", b"zTXt", b"iTXt"):
            chunks.append(data[at + 8 : at + 8 + length])
        at += 12 + length
    return chunks


def _inflated(data: bytes) -> List[bytes]:
    """Every zlib stream in a PDF's streams or a PNG's text chunks, inflated
    up to MAX_INFLATED in all."""
    parts = _PDF_STREAM.findall(data) if data.startswith(b"%PDF-") else _png_text_chunks(data) if data.startswith(b"\x89PNG") else []
    out, budget = [], MAX_INFLATED
    for part in parts:
        start = next((i for i in range(min(len(part), 200)) if part[i] == 0x78 and part[i : i + 2] in (b"x\x01", b"x^", b"x\x9c", b"x\xda")), None)
        if start is None or budget <= 0:
            continue
        try:
            text = zlib.decompressobj().decompress(part[start:], budget)
        except zlib.error:
            continue
        out.append(text)
        budget -= len(text)
    return out


def decoded_text(value: str) -> str:
    """The readable text inside a base64 image or PDF (raw and deflated PDF
    streams, PNG text chunks, JPEG comments, appended data), for scanning
    before the blob is skipped. Text drawn as pixels can't be read."""
    match = _BLOB.match(value)
    encoded = re.sub(r"\s", "", match.group(1)) if match else ""
    try:
        decoded = base64.b64decode(encoded.replace("-", "+").replace("_", "/") + "=" * (-len(encoded) % 4))
    except (binascii.Error, ValueError):
        return ""
    runs = [run for data in [decoded, *_inflated(decoded)] for run in re.findall(rb"[\x20-\x7e]{8,}", data)]
    return "\n".join(run.decode("ascii") for run in runs)


def deep_map(value: Any, fn: Callable[[str], str], map_keys: bool = True, blob_fn: Optional[Callable[[str], str]] = None) -> Any:
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
            target[slot] = blob_fn(source) if blob_fn else source
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

    def check_blob(blob: str) -> str:
        """An image or PDF is left intact unless its readable text hides a secret;
        then the whole blob is masked (it can't be edited in place)."""
        _, found = masker.mask(decoded_text(blob))
        if not found:
            return blob
        findings.extend(found)
        return masker.placeholder("binary-with-secret", blob)

    return deep_map(value, mask_string, blob_fn=check_blob), findings


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
