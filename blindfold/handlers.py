"""One pure function per hook event: (event, runtime) -> reply or None.

Reply shapes are the ones Claude Code and Grok both honour:
- PostToolUse: `updatedToolOutput` in the tool's own shape (Claude ignores
  anything else, a plain string included), plus `additionalContext`.
- PreToolUse: `permissionDecision: deny` with a reason.
- UserPromptSubmit: `decision: block` with a reason.
- Stop: `systemMessage`, shown to the user.
"""

import re
from typing import Any, Callable, Dict, List, Optional

from .bash import MARKER, unwrappable, wrap
from .events import Event
from .mask import PLACEHOLDER_RE, Finding
from .rules import PROMPT_BLOCKING_KINDS
from .runtime import Runtime
from .structure import mask_value, strings, withhold
from . import selfguard, shell, transcript

Reply = Optional[Dict[str, Any]]

WITHHELD = (
    "<blindfold: output withheld because the secret masker failed. The tool did run; "
    "don't re-run it blindly, ask the user to check `blindfold doctor`>"
)

SESSION_NOTE = """blindfold secret masking is active in this session. Secrets in tool results (file reads, command output, search, MCP) are replaced before you see them, and that is intended.

Placeholder: <blindfold kind=env:STRIPE_API_KEY len=107 id=3f9a1c>
- kind: why it was masked. env:NAME is the exact value of a known secret; a rule name (stripe-key, private-key, jwt, url-password, auth-header, env-assignment, named-secret, cli-secret-flag, high-entropy, ...) means it matched a secret's shape or name.
- len: the value's length. id: a keyed fingerprint, same value same id, not reversible.
- <blindfold: output withheld ...> means the masker failed and hid everything. The tool did run; don't re-run it blindly.
- "[blindfold: exit code N; reported as success so its output could be masked]" at the end of a command's output means the command FAILED with exit code N. Treat it as a failure.
- In Claude Code each Bash command runs in a subshell, so a `cd` doesn't carry over to the next command. Use absolute paths, or `cd dir && …` within one command.

Rules:
0. You are the first line of defence, blindfold is the safety net: be cautious with anything that is or might be sensitive, work blind by default, and don't read secret files, dump env vars or print config unless the task needs it (prefer commands that report names, presence or lengths). Masking can miss things.
1. Work blind: report secrets by name, presence, length and id, never by value. Let programs that load secrets themselves hold them. Compare by id.
2. Never try to recover a masked value: no re-reading another way (cat, head -c, xxd, od, strings, sed, base64, rev, tr, cut, a few characters at a time), no encoding, splitting or hashing to slip past the mask, no subagent or script to repeat it, no guessing from length, id or context.
3. Never write a placeholder into a file or command (it would replace the real secret; blindfold refuses it). Edit around masked parts.
4. Never disable, reconfigure or bypass blindfold yourself. blindfold refuses agent changes to its own code, config, key, skill and hook settings; the user makes those.
5. If a task needs a value you can't see, stop and ask the user, who can usually run one command.
6. False positive (something clearly not secret was masked): explain it, then propose the narrowest override, its id in allow_ids or a rule in disabled_rules in ~/.config/blindfold/config.json, and give the user the exact command to make it; you can't edit that file. Never propose allowing env:* kinds.
7. If a real secret's value is visible to you anywhere (a tool result blindfold missed, a user message, your own output), start your reply with "⚠️ SECRET EXPOSED: <name or kind>, seen in <where>. It reached the model provider and should be rotated." Never repeat the value. Name what to rotate."""


def summarize(findings: List[Finding]) -> str:
    kinds: Dict[str, int] = {}
    for finding in findings:
        kinds[finding.kind] = kinds.get(finding.kind, 0) + 1
    listed = ", ".join(f"{kind} x{count}" if count > 1 else kind for kind, count in sorted(kinds.items()))
    return (
        f"blindfold masked {len(findings)} potential secret(s) in this tool output ({listed}). "
        "The values are hidden on purpose: don't try to recover, guess or reconstruct them, "
        "and don't write a placeholder into a file. Work with names, lengths and ids instead."
    )


def _context(*parts: Optional[str]) -> str:
    return "\n\n".join(part for part in parts if part)


DRIFT_WARNING = (
    "blindfold did not recognise this tool event's result field (the agent's hook format may have changed), "
    "so it masked its best guess. Tell the user to run `blindfold selftest --agent <name>`."
)


def unmaskable_failure(event: Event, findings: List[Finding]) -> Reply:
    """Claude can't replace a failed call's output, so the model saw these raw: tell the user now."""
    kinds = ", ".join(sorted({f.kind for f in findings}))
    return {
        "systemMessage": (
            f"⚠️ blindfold: a failed {event.tool or 'tool'} call's output held {len(findings)} secret(s) ({kinds}). "
            "Claude Code doesn't let hooks mask a failed call's output, so they reached the model. Rotate them."
        ),
        "hookSpecificOutput": {
            "hookEventName": event.name,
            "additionalContext": (
                f"This failed call's output contained {len(findings)} secret(s) ({kinds}) that could NOT be masked. "
                "Tell the user loudly that they were exposed and must be rotated. Don't repeat or use them."
            ),
        },
    }


# The report bash.py appends to a failed command, as the last line of its stderr.
_EXIT_REPORT = re.compile(re.escape(MARKER) + r" (\d+|nonzero);[^\]\n]*\]\s*$")


def failure_note(event: Event) -> Optional[str]:
    """A wrapped command that failed looks like a success to the agent, with only
    a line at the end of stderr to say otherwise: say it where it can't be missed."""
    if event.is_grok or event.tool != "Bash":
        return None
    code = next((m.group(1) for text in strings(event.result) for m in [_EXIT_REPORT.search(text)] if m), None)
    if code is None:
        return None
    return (
        f"This command exited with {'a nonzero code' if code == 'nonzero' else f'code {code}'}: it FAILED (for grep, diff or test, it may only mean no match or a "
        "difference). blindfold reports it as a success only so its output could be masked."
    )


def post_tool_use(event: Event, rt: Runtime) -> Reply:
    if event.result_key is None:
        return None
    masked, findings = mask_value(rt.masker, event.result)
    if findings and event.name == "PostToolUseFailure" and not event.is_grok:
        return unmaskable_failure(event, findings)
    note = _context(
        failure_note(event),
        summarize(findings) if findings else None,
        None if event.result_key_is_known else DRIFT_WARNING,
        rt.warning,
    )
    if not findings:
        return {"hookSpecificOutput": {"hookEventName": event.name, "additionalContext": note}} if note else None
    return {"hookSpecificOutput": {"hookEventName": event.name, "updatedToolOutput": masked, "additionalContext": note}}


def _deny(reason: str) -> Dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}


def known_names_in(rt: Runtime, texts: List[str]) -> List[str]:
    """Known secrets whose real value is in texts. Word-like values don't count:
    they also turn up in ordinary text, so they never refuse a call or alarm."""
    _, findings = rt.masker.mask("\n".join(texts)) if texts else ("", [])
    return sorted({f.kind[4:] for f in findings if f.kind.startswith("env:") and not f.weak})


BLOCKED_COMMAND_REASON = (
    "blindfold: this command prints a secret on its own (a Keychain or 1Password read), which can't be "
    "masked because nothing marks it as a secret. Use a tool that consumes the secret itself "
    "(`op run`, a CLI that loads its own credentials), or ask the user to run it."
)


def _command(event: Event) -> Optional[str]:
    command = event.tool_input.get("command") if isinstance(event.tool_input, dict) else None
    return command if isinstance(command, str) else None


def _is_blocked_command(event: Event, patterns: List[str]) -> bool:
    """A heredoc fed to cat or tee is data (docs, notes), so it isn't judged."""
    command = _command(event)
    if command is None:
        return False
    judged = shell.strip_data_heredocs(command)
    return any(re.search(pattern, judged, re.MULTILINE) for pattern in patterns)


_DOC_FILE = re.compile(r"\.(?:md|mdx|markdown|rst)$", re.IGNORECASE)


def _writes_docs(event: Event) -> bool:
    """A file tool writing a doc, where a placeholder is an example, not a stand-in for a value."""
    tool_input = event.tool_input if isinstance(event.tool_input, dict) else {}
    paths = [v for k in ("file_path", "filePath", "path", "target_file") for v in [tool_input.get(k)] if isinstance(v, str)]
    return "command" not in tool_input and bool(paths) and all(_DOC_FILE.search(p) for p in paths)


# When the full check failed (or ran out of time), a linear-time stand-in: any
# command naming the Keychain or 1Password CLI is refused.
_MAYBE_BLOCKED = re.compile(r"\b(?:op|security)\b")


def pre_tool_use(event: Event, rt: Runtime) -> Reply:
    texts = event.tool_input_texts
    if _is_blocked_command(event, rt.config.blocked_commands):
        return _deny(BLOCKED_COMMAND_REASON)
    changes_blindfold = selfguard.reason(event.tool_input, event.is_read_only_tool, event.cwd)
    if changes_blindfold:
        return _deny(
            f"blindfold: this call would change blindfold itself ({changes_blindfold}). Agents don't modify "
            "blindfold's installed code, config, key, skill or hook settings, so masking can't be switched off by "
            "accident. Tell the user the exact change and let them make it (they can type `! <command>`)."
        )
    guard = rt.config.guard_placeholders and not event.is_read_only_tool and not _writes_docs(event)
    if guard and any(PLACEHOLDER_RE.search(t) for t in texts):
        return _deny(
            "blindfold: this call contains a masked-secret placeholder (<blindfold kind= …>). The real value is what "
            "belongs there, so writing or sending the placeholder would replace or corrupt it, and an "
            "old_string containing one can't match the file. Edit around the masked part (pick an old_string "
            "that excludes it), leave that value as it is, or ask the user to change it."
        )
    if rt.config.guard_known_values:
        leaked = known_names_in(rt, texts)
        if leaked:
            return _deny(
                "blindfold: this call contains the actual value of a known secret "
                f"({', '.join(leaked)}). It must not be in a command, file or request. Stop and tell the user "
                "LOUDLY that the secret reached the agent's context and should be rotated."
            )
    return _wrapped_bash(event, rt)


UNWRAPPABLE_REASON = (
    "blindfold: in a worktree session Claude Code only runs a git command written as one plain line, and in that "
    "form blindfold can't mask a failing command's output if it has several lines, a heredoc, a comment, a trailing "
    "& or ;, or exit/set/exec/trap/eval/source. Run it as separate single-line commands."
)


def _wrapped_bash(event: Event, rt: Runtime) -> Reply:
    """Claude only: rewrite a Bash command to exit 0 so its output can be masked (see bash.py)."""
    tool_input = event.tool_input
    if event.is_grok or event.tool != "Bash" or not rt.config.wrap_claude_bash or not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if isinstance(command, str) and unwrappable(command, event.cwd):
        return _deny(UNWRAPPABLE_REASON)
    wrapped = wrap(command, event.cwd) if isinstance(command, str) else None
    if wrapped is None or wrapped == command:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": {**tool_input, "command": wrapped}}}


def user_prompt_submit(event: Event, rt: Runtime) -> Reply:
    texts = event.prompt_texts
    _, findings = rt.masker.mask("\n".join(texts)) if texts else ("", [])
    blocking = [f for f in findings if (f.kind.startswith("env:") and not f.weak) or f.kind in PROMPT_BLOCKING_KINDS]
    if not blocking:
        return None
    found = ", ".join(sorted({f"{f.kind[4:] if f.kind.startswith('env:') else f.kind} (id {f.fingerprint})" for f in blocking}))
    return {
        "decision": "block",
        "reason": (
            f"⚠️ blindfold: your prompt contains what looks like a real secret: {found}. It was blocked before reaching "
            "the model. Remove the value and send it again, referring to the secret by name. If it isn't secret, "
            "add its id to allow_ids in ~/.config/blindfold/config.json."
        ),
    }


def stop(event: Event, rt: Runtime) -> Reply:
    texts = list(event.last_message_texts)
    # Grok's transcript keeps every original output by design, so only Claude's
    # (which stores the masked version) can show a value that got through.
    if event.transcript_path and not event.is_grok:
        texts.append(transcript.tail(event.transcript_path))
    names = known_names_in(rt, texts)
    if not names:
        return None
    return {
        "systemMessage": (
            f"⚠️ blindfold: the actual value of {', '.join(names)} reached the model this session (in the agent's "
            "reply, a tool result blindfold didn't mask, or a prompt). Treat it as exposed and rotate it."
        )
    }


def session_start(_event: Event, rt: Runtime) -> Reply:
    return {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": _context(SESSION_NOTE, rt.warning)}}


HANDLERS: Dict[str, Callable[[Event, Runtime], Reply]] = {
    "PostToolUse": post_tool_use,
    "PostToolUseFailure": post_tool_use,
    "PreToolUse": pre_tool_use,
    "UserPromptSubmit": user_prompt_submit,
    "Stop": stop,
    "SessionStart": session_start,
}


def handle(event: Event, rt: Runtime) -> Reply:
    handler = HANDLERS.get(event.name)
    return handler(event, rt) if handler else None


def withheld_reply(event: Event) -> Reply:
    """The fail-closed reply when masking itself failed."""
    if event.name in ("PostToolUse", "PostToolUseFailure") and event.result_key is not None:
        return {
            "hookSpecificOutput": {
                "hookEventName": event.name,
                "updatedToolOutput": withhold(event.result, WITHHELD),
                "additionalContext": "blindfold failed while masking this output, so all of its text was withheld.",
            }
        }
    # Before a call or prompt, a failure lets it through: the security boundary
    # is masking the output afterwards (which still withholds on failure), and
    # refusing everything would lock the user and every agent out over a bug.
    if event.name == "PreToolUse":
        # Except for commands that may print a bare secret, which masking
        # afterwards can't recognise.
        if _MAYBE_BLOCKED.search(_command(event) or ""):
            return _deny(BLOCKED_COMMAND_REASON)
        note = "blindfold's pre-call check failed, so this call was allowed unchecked. Tell the user to run `blindfold doctor`."
        reply: Dict[str, Any] = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": note}}
        # The guards are skipped, but Claude's Bash wrapper is kept: without it a
        # failing command's output couldn't be masked.
        command = event.tool_input.get("command") if isinstance(event.tool_input, dict) else None
        if not event.is_grok and event.tool == "Bash" and isinstance(command, str):
            reply["hookSpecificOutput"]["updatedInput"] = {**event.tool_input, "command": wrap(command, event.cwd)}
        return reply
    if event.name == "UserPromptSubmit":
        return {"systemMessage": "⚠️ blindfold could not check this prompt for secrets (run `blindfold doctor`). It was sent unchecked."}
    return None
