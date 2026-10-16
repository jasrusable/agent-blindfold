"""Rewriting Claude Code Bash commands so their output can always be masked.

Claude Code only lets a hook replace the output of a tool call that succeeded
(PostToolUse). A command that exits non-zero goes through PostToolUseFailure,
whose output can't be replaced: `cat .env; exit 1` would show its secrets raw.
So blindfold makes each Bash command exit 0 and report the real exit code instead.
Grok doesn't need this: its PostToolUse covers failures too.

The command runs in a `{ … }` group in the same shell, so `cd` persists to the
next call as usual. An EXIT trap catches the ways the shell itself can die
(`exit`, `set -e`, `${X:?}`, a sourced script that exits) and turns them into
the same report and exit 0. A command that could get around the trap runs in
a `( … )` subshell instead: nounset (zsh skips EXIT traps when it kills the
shell), `exec` (replaces the shell) and `trap` (could replace ours). That costs
that one call its `cd` persistence. The status is never tested
with `||`, which would silently disable `set -e`. Verified against real Claude: masking on
every exit path, `cd` persisting, allow rules still matching and deny rules
still enforced.

Not covered: a command Claude kills (its timeout, or Esc), and `kill $$`.
Their output goes down the failure path, and blindfold warns the user instead
(handlers.py). Trapping TERM/INT would change how commands stop when asked to.
"""

import re

MARKER = "[blindfold: exit code"
_REPORT = (
    'blindfold_rc=$?; trap - EXIT; [ "$blindfold_rc" -eq 0 ] || '
    f"printf '\\n{MARKER} %s; reported as success so its output could be masked]\\n' \"$blindfold_rc\" >&2"
)
# Run in a subshell, where they can't stop the parent reporting: nounset in any
# spelling (zsh skips EXIT traps when it kills the shell), `exec` (replaces the
# shell, so no EXIT trap runs), and `trap` (could replace or clear ours).
_NEEDS_SUBSHELL = re.compile(
    r"\bset\s+-[A-Za-z]*u|nounset|no_?unset|(?:^|[;&|({]|\bthen|\bdo|\belse)\s*exec\b|\btrap\b",
    re.IGNORECASE | re.MULTILINE,
)



def _only_comments(command: str) -> bool:
    """Blank lines and comments only: wrapped, that is an empty group, a syntax error."""
    return all(not line.strip() or line.strip().startswith("#") for line in command.splitlines())


_TRAP = "trap '" + _REPORT.replace("'", "'\\''") + "; exit 0' EXIT"


def wrap(command: str) -> str:
    """The command made to exit 0, reporting a failure's code on stderr.

    Already wrapped is recognised by the exact trap line (a command that merely
    mentions the marker is still wrapped). The blank line before the closing
    brace absorbs a trailing `\\` line continuation.
    """
    if command.startswith(_TRAP) or _only_comments(command):
        return command
    opening, closing = ("(", ")") if _NEEDS_SUBSHELL.search(command) else ("{", "}")
    return f"{_TRAP}\n{opening}\n{command}\n\n{closing}\n{_REPORT}"
