"""Rewriting Claude Code Bash commands so their output can always be masked.

Claude Code only lets a hook replace the output of a tool call that succeeded
(PostToolUse). A command that exits non-zero goes through PostToolUseFailure,
whose output can't be replaced: `cat .env; exit 1` would show its secrets raw.
So blindfold makes each Bash command exit 0 and report the real exit code instead.
Grok doesn't need this: its PostToolUse covers failures too.

The command runs in a `( … )` subshell and the parent reports its status, so
every way the command can end its shell (`exit`, `set -e`, `${X:?}`, nounset,
`exec`, zsh's "no matches found", a sourced script that exits) ends only the
subshell. No `trap`: Claude Code's worktree-isolation guard can't verify a trap's
body and refuses every command that has one. The status is never tested with
`||`, which would silently disable `set -e`, and the report itself succeeds, so
Claude Code's own `&& pwd -P >| <cwd file>` after it still runs.

The cost: Claude Code keeps the working directory between calls by running
`pwd -P` in the parent shell after the command, so a `cd` inside the subshell
no longer carries over to the next call. `cd dir && cmd` within one call works.
The selftest checks through real Claude that failing commands are masked, allow
rules still match and deny rules are still enforced.

Not covered: a command Claude kills (its timeout, or Esc), and `kill $$`.
Their output goes down the failure path, and blindfold warns the user instead
(handlers.py). Trapping TERM/INT would change how commands stop when asked to.
"""

MARKER = "[blindfold: exit code"
_REPORT = (
    'blindfold_rc=$?; [ "$blindfold_rc" -eq 0 ] || '
    f"printf '\\n{MARKER} %s; reported as success so its output could be masked]\\n' \"$blindfold_rc\" >&2"
)
# The blank line before the closing parenthesis ends a trailing `\` line
# continuation or comment, and closes nothing else: a here-document's
# delimiter line has already been read.
_OPEN, _CLOSE = "(\n", f"\n\n)\n{_REPORT}"


def _only_comments(command: str) -> bool:
    """Blank lines and comments only: wrapped, that is an empty subshell, a syntax error."""
    return all(not line.strip() or line.strip().startswith("#") for line in command.splitlines())


def wrap(command: str) -> str:
    """The command made to exit 0, reporting a failure's code on stderr.

    Always wrapped, even when it looks wrapped already: a command crafted to
    look wrapped would otherwise run bare, and wrapping twice is harmless (the
    inner report succeeds, so the outer one says nothing)."""
    return command if _only_comments(command) else f"{_OPEN}{command}{_CLOSE}"
