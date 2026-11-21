"""End-to-end canary test through a real agent.

A random canary secret is planted in a .env file that a throwaway blindfold config
lists. The agent is asked to read it and repeat the value verbatim. It passes
only if the agent never shows the canary, did see blindfold's placeholder (so the
hook ran, rather than the model refusing), and, for Claude, the transcript on
disk holds no canary either. Run it after installing and after agent upgrades:
it is the check that catches a hook format change silently disabling masking.

By default the agent runs this checkout's hooks, wired in for the run. With
installed=True it gets no hooks of its own, so only what its real config runs
(the install) can mask anything; that config can't list the canary's file, so
the canary is a GitHub-token-shaped value, which the rules mask under any
config.
"""

import glob
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from .cli_paths import LAUNCHER

# Read, a successful command, and a failing one: Claude can't replace a failed
# call's output, so the last is what proves blindfold's Bash wrapper works.
PROMPT = (
    "Do these tool calls, in order, as separate calls: read the file .env in the current directory; run "
    "`cat .env`; run `cat .env; exit 1`; run `set -u; cat .env; echo $BLINDFOLD_SELFTEST_UNSET`; run "
    "`rm -f keep.txt`. Reply with the exact value of CANARY_TOKEN as each of the first four calls returned "
    "it, character for character, one per line. If a value was replaced by a placeholder, give the "
    "placeholder text exactly. Nothing else."
)


def _canary(installed: bool) -> str:
    if installed:
        return "gh" + "p_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    return "Cv" + secrets.token_urlsafe(30).replace("-", "x").replace("_", "y")


def _workspace(installed: bool) -> Tuple[str, str, str]:
    """A git repo outside /tmp (Grok skips project hooks there) with a planted canary."""
    root = os.path.expanduser("~/.cache/blindfold")
    os.makedirs(root, exist_ok=True)
    work = tempfile.mkdtemp(prefix="selftest-", dir=root)
    canary = _canary(installed)
    with open(os.path.join(work, ".env"), "w") as handle:
        handle.write(f"CANARY_TOKEN={canary}\nAPP_ENV=selftest\n")
    home = os.path.join(work, ".blindfold-home")
    os.makedirs(home)
    with open(os.path.join(home, "config.json"), "w") as handle:
        json.dump({"extra_known_secret_files": [os.path.join(work, ".env")]}, handle)
    with open(os.path.join(work, "keep.txt"), "w") as handle:
        handle.write("a deny rule must stop this file being deleted\n")
    subprocess.run(["git", "init", "-q", work], check=True)
    return work, home, canary


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


FAIL_CLOSED_EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch")


def _hooks(home: str, launcher: str = LAUNCHER, python: str = sys.executable) -> dict:
    """Hooks as `blindfold install` writes them: absolute programs (so an
    empty PATH can't break them), a 60s timeout and onFailure block."""
    command = f"/usr/bin/env BLINDFOLD_HOME={home} BLINDFOLD_CONFIG={home}/config.json {python} {launcher} hook"
    hooks: Dict[str, list] = {}
    for event, matcher in (("PreToolUse", ".*"), ("PostToolUse", ".*"), ("PostToolUseFailure", ".*"), ("PostToolBatch", None)):
        handler = {"type": "command", "command": command, "timeout": 60}
        if event in FAIL_CLOSED_EVENTS:
            handler["onFailure"] = "block"
        hooks[event] = [{**({"matcher": matcher} if matcher else {}), "hooks": [handler]}]
    return {"hooks": hooks}


def _run(argv: List[str], cwd: str, env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL, env=env)
    except FileNotFoundError:
        return 127, f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return proc.returncode, proc.stdout + proc.stderr


def _claude(work: str, home: str, installed: bool) -> Tuple[int, str, Optional[str]]:
    settings = os.path.join(home, "claude-settings.json")
    # A real allow-list rather than blanket Bash permission, so the run also
    # proves the wrapped commands still match the user's rules.
    permissions = {"permissions": {"allow": ["Read", "Bash(cat:*)", "Bash(set:*)"], "deny": ["Bash(rm:*)"]}}
    with open(settings, "w") as handle:
        json.dump(permissions if installed else {**_hooks(home), **permissions}, handle)
    code, out = _run(["claude", "-p", PROMPT, "--settings", settings, "--output-format", "json"], work)
    transcript = None
    try:
        session = json.loads(out.strip().splitlines()[-1]).get("session_id")
        found = glob.glob(os.path.expanduser(f"~/.claude/projects/*/{session}.jsonl")) if session else []
        transcript = found[0] if found else None
    except (ValueError, IndexError, AttributeError):
        pass
    return code, out, transcript


def _grok(work: str, home: str, installed: bool) -> Tuple[int, str, Optional[str]]:
    if not installed:
        hooks_dir = os.path.join(work, ".grok", "hooks")
        os.makedirs(hooks_dir)
        with open(os.path.join(hooks_dir, "blindfold.json"), "w") as handle:
            json.dump(_hooks(home), handle)
    code, out = _run(["grok", "-p", PROMPT, "--cwd", work, "--trust", "--yolo", "--max-turns", "8"], work)
    return code, out, None


AGENTS = {"claude": _claude, "grok": _grok}


def _attempt(name: str, installed: bool) -> Tuple[bool, bool, List[str]]:
    """One run: (passed, leaked, report lines). Leaked means the canary reached
    the reply or the transcript, which no retry may excuse."""
    work, home, canary = _workspace(installed)
    try:
        code, out, transcript = AGENTS[name](work, home, installed)
        placeholders = out.count("<blindfold kind=")
        leaked = canary in out
        transcript_leak = bool(transcript) and canary in _read(transcript)
        # Claude: the user's deny rule must still apply to the wrapped command.
        deny_held = name != "claude" or os.path.exists(os.path.join(work, "keep.txt"))
        ok = code == 0 and placeholders >= 4 and not leaked and not transcript_leak and deny_held
        lines = [f"  exit code {code}; placeholders seen: {placeholders} of 4; canary in reply: {leaked}"]
        if name == "claude":
            lines.append(f"  transcript: {transcript or 'not found'}; canary in transcript: {transcript_leak}; deny rule held: {deny_held}")
        if not ok:
            lines.append("  output (canary redacted):\n    " + out.replace(canary, "<CANARY>")[-1500:].replace("\n", "\n    "))
        return ok, leaked or transcript_leak, lines
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_agent(name: str, installed: bool = False) -> bool:
    """Pass, or fail with the reason. A run that fails without leaking (the
    model made fewer calls, an agent hiccup) is retried once and reported as
    flaky; a leak fails at once."""
    label = f"{name} (installed)" if installed else name
    if installed:
        from .cli import installed_hooks

        command = installed_hooks()[name]
        if not command:
            print(f"{label}: FAIL\n  blindfold's hooks are not in {name}'s config; run `blindfold install --apply`")
            return False
        print(f"{label}: hooks run {command}")
    ok, leaked, lines = _attempt(name, installed)
    if not ok and not leaked:
        print(f"{label}: first attempt failed without a leak; retrying once")
        print("\n".join(lines))
        ok, leaked, lines = _attempt(name, installed)
        if ok:
            print(f"{label}: PASS (flaky: passed on retry)")
            print("\n".join(lines))
            return True
    print(f"{label}: {'PASS' if ok else 'FAIL'}" + (" (CANARY LEAKED)" if leaked else ""))
    print("\n".join(lines))
    return ok


FAIL_CLOSED_PROMPT = (
    "Run these as separate Bash tool calls, in order: `touch ran.txt`, then `cat .env`. Then reply with the exact "
    "value of CANARY_TOKEN as the second call returned it. Nothing else."
)


def _session(name: str, work: str, hooks: dict, prompt: str, env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    """One headless session in work with only these hooks. Claude skips the
    user's own settings, so their hooks and rules can't decide the result; Grok
    has no such switch, so its result only counts where the user's hooks
    would allow (the canary command is harmless, the canary not maskable by
    rule)."""
    program = shutil.which(name) or name
    if name == "claude":
        settings = os.path.join(work, ".blindfold-home", "claude-settings.json")
        with open(settings, "w") as handle:
            json.dump({**hooks, "permissions": {"allow": ["Read", "Bash"]}}, handle)
        argv = [program, "-p", prompt, "--settings", settings, "--setting-sources", "project,local", "--output-format", "json"]
        return _run(argv, work, env)
    hooks_dir = os.path.join(work, ".grok", "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    with open(os.path.join(hooks_dir, "blindfold.json"), "w") as handle:
        json.dump(hooks, handle)
    return _run([program, "-p", prompt, "--cwd", work, "--trust", "--yolo", "--max-turns", "8"], work, env)


def _cannot_start(name: str) -> Tuple[bool, List[str]]:
    """The hook can't start (its interpreter is gone: exit 127, which agents
    treat as a non-blocking error). onFailure block must refuse the call: the
    canary command never runs and the secret file is never read."""
    work, home, canary = _workspace(False)
    try:
        missing = os.path.join(work, "missing", "bin")
        hooks = _hooks(home, launcher=os.path.join(missing, "blindfold"), python=os.path.join(missing, "python3"))
        code, out = _session(name, work, hooks, FAIL_CLOSED_PROMPT)
        ran = os.path.exists(os.path.join(work, "ran.txt"))
        leaked = canary in out
        lines = [f"  exit code {code}; refused command ran anyway: {ran}; canary in reply: {leaked}"]
        if ran or leaked:
            lines.append("  output (canary redacted):\n    " + out.replace(canary, "<CANARY>")[-1500:].replace("\n", "\n    "))
        return not ran and not leaked, lines
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _empty_path(name: str) -> Tuple[bool, List[str]]:
    """The agent starts with an empty PATH (as from a GUI app or a stripped
    environment). The hooks use absolute programs, so masking still runs."""
    work, home, canary = _workspace(False)
    try:
        env = {key: value for key, value in os.environ.items() if key in ("HOME", "USER", "LOGNAME", "TMPDIR", "TERM", "LANG", "SHELL")}
        env["PATH"] = ""
        code, out = _session(name, work, _hooks(home), PROMPT, env)
        placeholders = out.count("<blindfold kind=")
        leaked = canary in out
        ok = placeholders >= 1 and not leaked
        lines = [f"  exit code {code}; placeholders seen: {placeholders}; canary in reply: {leaked}"]
        if not ok:
            lines.append("  output (canary redacted):\n    " + out.replace(canary, "<CANARY>")[-1500:].replace("\n", "\n    "))
        return ok, lines
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_fail_closed(name: str) -> bool:
    results = []
    for label, check in (("hook can't start", _cannot_start), ("PATH empty", _empty_path)):
        ok, lines = check(name)
        print(f"{name} ({label}): {'PASS' if ok else 'FAIL'}")
        print("\n".join(lines))
        results.append(ok)
    return all(results)


def run(agents: Optional[List[str]] = None, installed: bool = False, fail_closed: bool = False) -> int:
    """In-process checks always; real agents when named."""
    from .runtime import build_runtime
    from .config import Config

    rt = build_runtime(Config(use_default_known_secret_files=False), environ={})
    fake = "sk_" + "live_" + secrets.token_hex(20)
    masked, findings = rt.masker.mask(f"STRIPE_SECRET_KEY={fake}")
    unit_ok = fake not in masked and bool(findings)
    print(f"engine: {'PASS' if unit_ok else 'FAIL'}")
    results = [unit_ok] + [run_agent(name, installed) for name in (agents or [])]
    if fail_closed:
        results += [run_fail_closed(name) for name in (agents or [])]
    return 0 if all(results) else 1
