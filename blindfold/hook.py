"""Process entry point for Claude Code and Grok hooks: stdin event, stdout reply.

A hook that crashes, times out or exits non-zero fails open in both agents
unless its entry sets "onFailure": "block" (which `blindfold install` writes,
and which Grok honours only before a call or prompt). So nothing here may
raise. Any failure turns into the fail-closed reply (output withheld, call
refused, prompt blocked, turn stopped), and input that can't be parsed exits 2,
which blocks a pending call or prompt.
"""

import contextlib
import json
import os
import select
import signal
import sys
import time
from typing import Any, Dict, Optional

from .events import Event
from .handlers import FAILED_CHECK_REASON, FAILED_PROMPT_REASON, handle, withheld_reply
from .runtime import Runtime, load_runtime


# Well under the hook timeout `blindfold install` writes (60s): past this, the
# fail-closed reply, rather than leave it to how the agent treats a timeout.
BUDGET_SECONDS = 20


class _OverBudget(Exception):
    pass


def _over_budget(_signum, _frame):
    raise _OverBudget()


def last_resort(raw: Dict[str, Any], cause: str) -> Optional[Dict[str, Any]]:
    """When even the fail-closed reply failed: refuse, block or stop by event name
    alone. PostToolUse gets nothing: with no output to withhold, PostToolBatch
    (Claude) stops the turn because the call wasn't recorded as handled."""
    name = raw.get("hook_event_name")
    if name == "PreToolUse":
        reason = FAILED_CHECK_REASON.format(cause=cause)
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
    if name in ("UserPromptSubmit", "PostToolBatch"):
        return {"decision": "block", "reason": FAILED_PROMPT_REASON.format(cause=cause)}
    return None


def _fail_closed(raw: Dict[str, Any], cause: str) -> Optional[Dict[str, Any]]:
    try:
        return withheld_reply(Event(raw), cause)
    except Exception:  # noqa: BLE001
        return last_resort(raw, cause)


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
        cause = "it ran past its time budget" if isinstance(error, _OverBudget) else f"internal error: {type(error).__name__}"
        print(f"blindfold: {cause}", file=sys.stderr)
        return _fail_closed(raw, cause)
    finally:
        if timed:
            signal.alarm(0)


def respond_with_deadline(raw: Dict[str, Any], seconds: float = BUDGET_SECONDS + 2) -> Optional[Dict[str, Any]]:
    """respond() in a forked child, killed at the deadline. SIGALRM only fires
    between bytecodes, so one slow regex call could otherwise run past the
    agent's hook timeout, which fails open."""
    if not hasattr(os, "fork"):
        return respond(raw)
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            payload = json.dumps(respond(raw), ensure_ascii=True).encode("ascii")
            with os.fdopen(writer, "wb") as out:
                out.write(payload)
        finally:
            os._exit(0)
    os.close(writer)
    chunks, deadline = [], time.monotonic() + seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([reader], [], [], remaining)[0]:
                raise TimeoutError()
            chunk = os.read(reader, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except Exception:  # noqa: BLE001 - incl. the deadline and a child that died
        print("blindfold: masking ran past its deadline or crashed", file=sys.stderr)
        return _fail_closed(raw, "it ran past its deadline or crashed")
    finally:
        os.close(reader)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


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
    reply = respond_with_deadline(raw)
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
