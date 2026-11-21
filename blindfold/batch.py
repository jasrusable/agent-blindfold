"""The backstop for a masking hook that failed to run.

A PostToolUse hook that can't start, crashes or times out fails open: the tool's
raw output goes to the model. Claude Code's PostToolBatch hook runs once all of
a batch's calls have resolved, before the next model call, and can stop the
turn. So PostToolUse records each call it handled, and PostToolBatch stops the
turn when a call's output holds something maskable that no PostToolUse handled.

Records live under blindfold's config directory, which the self-guard keeps
agents from writing to, keyed by hashes of the session and tool-use ids.
"""

import hashlib
import os
import shutil
import time
from typing import Optional

from .config import CONFIG_DIR

STATE_DIR = os.path.join(CONFIG_DIR, "batch")
_STALE_SECONDS = 2 * 24 * 3600


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _path(session_id: str, tool_use_id: str) -> str:
    return os.path.join(STATE_DIR, _digest(session_id), _digest(tool_use_id))


def mark_handled(session_id: Optional[str], tool_use_id: Optional[str]) -> None:
    if not isinstance(session_id, str) or not isinstance(tool_use_id, str) or not tool_use_id:
        return
    path = _path(session_id, tool_use_id)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "w", encoding="ascii"):
        pass


def take_handled(session_id: Optional[str], tool_use_id: Optional[str]) -> bool:
    """Whether PostToolUse handled this call; the record is used up."""
    if not isinstance(session_id, str) or not isinstance(tool_use_id, str) or not tool_use_id:
        return False
    try:
        os.remove(_path(session_id, tool_use_id))
        return True
    except OSError:
        return False


def prune(now: Optional[float] = None) -> None:
    """Drop the records of sessions untouched for two days."""
    now = time.time() if now is None else now
    try:
        entries = list(os.scandir(STATE_DIR))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir() and now - entry.stat().st_mtime > _STALE_SECONDS:
                shutil.rmtree(entry.path, ignore_errors=True)
        except OSError:
            continue
