"""Process entry point for Claude Code and Grok hooks: stdin event, stdout reply.

A hook that crashes, times out or exits non-zero fails open in both agents: the
original output reaches the model. So nothing here may raise. Any failure turns
into the fail-closed reply (output withheld, call or prompt blocked), and input
that can't be parsed exits 2, which blocks a pending call or prompt.
"""

import json
import os
import signal
import sys
import time
from typing import Any, Dict, Optional

from .events import Event
from .handlers import handle, withheld_reply
from .runtime import Runtime, load_runtime


# Under the agents' hook timeout (30s), which fails open: past this, withhold.
BUDGET_SECONDS = 20


class _OverBudget(Exception):
    pass


def _over_budget(_signum, _frame):
    raise _OverBudget()


def respond(raw: Dict[str, Any], rt: Optional[Runtime] = None) -> Optional[Dict[str, Any]]:
    """The reply for one event; never raises, and never takes longer than the budget."""
    event = Event(raw)
    timed = hasattr(signal, "SIGALRM")
    try:
        if timed:
            signal.signal(signal.SIGALRM, _over_budget)
            signal.alarm(BUDGET_SECONDS)
        return handle(event, rt or load_runtime())
    except BaseException as error:  # noqa: BLE001 - must never fail open, incl. the budget
        print(f"blindfold: internal error: {type(error).__name__}", file=sys.stderr)
        try:
            return withheld_reply(event)
        except Exception:  # noqa: BLE001
            return None
    finally:
        if timed:
            signal.alarm(0)


def main() -> int:
    started = time.monotonic()
    try:
        raw = json.loads(sys.stdin.buffer.read().decode("utf-8", "surrogatepass"))
        if not isinstance(raw, dict):
            raise ValueError("hook input is not a JSON object")
    except Exception:  # noqa: BLE001 - incl. RecursionError on absurd nesting
        # No structure to mask or withhold. Exit 2 blocks a pending tool call or
        # prompt in both agents, the fail-closed direction where one exists.
        print("blindfold: could not read the hook input, so this step was blocked", file=sys.stderr)
        return 2
    reply = respond(raw)
    if reply is not None:
        try:
            # ASCII-only JSON can't fail to encode, whatever the output held.
            payload = json.dumps(reply, ensure_ascii=True)
        except Exception:  # noqa: BLE001
            print("blindfold: could not encode the reply, so this step was blocked", file=sys.stderr)
            return 2
        sys.stdout.write(payload)
        sys.stdout.flush()
    if os.environ.get("BLINDFOLD_DEBUG_TIMING"):
        print(f"blindfold: {1000 * (time.monotonic() - started):.1f}ms", file=sys.stderr)
    return 0
