"""The tail of a session transcript, for the end-of-turn leak check.

Claude Code writes the masked tool output to its transcript when a replacement
is applied, so a known secret's raw value in the tail means it reached the
model: through a channel blindfold doesn't see, the agent's own reply, or a masking
replacement the agent silently ignored (for example after an API change).
"""

import os

TAIL_BYTES = 1024 * 1024


def tail(path: str) -> str:
    """The last TAIL_BYTES of the file as text, or "" if it can't be read."""
    try:
        with open(os.path.expanduser(path), "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - TAIL_BYTES))
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""
