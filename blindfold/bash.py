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

In a worktree-isolated session (EnterWorktree, `claude --worktree`) Claude
Code also refuses any command that names git together with something it can't
verify, a subshell or any `$` expansion included (seen on 2.1.306). There a
git command gets the one form it accepts, `cmd || printf '…' >&2`, which can't
say the exit code; a git command that form can't hold safely (several lines,
a heredoc or comment, or `exit`/`set`/`exec`/`trap`/`eval`/`source`) is
refused, with a reason asking for single-line commands: unwrapped, a failure's
output couldn't be masked.

Not covered: a command Claude kills (its timeout, or Esc), and `kill $$`.
Their output goes down the failure path, and blindfold warns the user instead
(handlers.py). Trapping TERM/INT would change how commands stop when asked to.
"""

import re
from typing import Optional

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


_ISOLATED_WORKTREE = re.compile(r"/\.claude/worktrees/[^/]+/")
_NAMES_GIT = re.compile(r"(?:^|[\s;&|(`])git(?:\s|$)")
# What a top-level `cmd || report` can't hold: more than one line, a heredoc, a
# comment or line continuation, a trailing & or ;, or a builtin that can end
# the shell before the report runs.
_NOT_ONE_PLAIN_LINE = re.compile(r"\n|<<|#|\\\s*$|[&;]\s*$|\b(?:exit|exec|set|setopt|trap|eval|source)\b|(?:^|[;&|(]\s*)\.\s")
_NONZERO_REPORT = f"printf '\\n{MARKER} nonzero; reported as success so its output could be masked]\\n' >&2"


def _git_in_worktree(command: str, cwd: Optional[str]) -> bool:
    return bool(cwd and _ISOLATED_WORKTREE.search(cwd + "/") and _NAMES_GIT.search(command))


def unwrappable(command: str, cwd: Optional[str] = None) -> bool:
    """A git command in a worktree session that no form the guard accepts can hold."""
    return _git_in_worktree(command, cwd) and not _only_comments(command) and bool(_NOT_ONE_PLAIN_LINE.search(command))


def wrap(command: str, cwd: Optional[str] = None) -> str:
    """The command made to exit 0, reporting a failure's code on stderr.

    Always wrapped, even when it looks wrapped already: a command crafted to
    look wrapped would otherwise run bare, and wrapping twice is harmless (the
    inner report succeeds, so the outer one says nothing)."""
    if _only_comments(command):
        return command
    if _git_in_worktree(command, cwd):
        return command if _NOT_ONE_PLAIN_LINE.search(command) else f"{command} || {_NONZERO_REPORT}"
    return f"{_OPEN}{command}{_CLOSE}"
