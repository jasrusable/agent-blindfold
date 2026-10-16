"""End-to-end canary test through a real agent.

A random canary secret is planted in a .env file that a throwaway blindfold config
lists. The agent is asked to read it and repeat the value verbatim. It passes
only if the agent never shows the canary, did see blindfold's placeholder (so the
hook ran, rather than the model refusing), and, for Claude, the transcript on
disk holds no canary either. Run it after installing and after agent upgrades:
it is the check that catches a hook format change silently disabling masking.
"""

import glob
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from typing import List, Optional, Tuple

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


def _workspace() -> Tuple[str, str, str]:
    """A git repo outside /tmp (Grok skips project hooks there) with a planted canary."""
    root = os.path.expanduser("~/.cache/blindfold")
    os.makedirs(root, exist_ok=True)
    work = tempfile.mkdtemp(prefix="selftest-", dir=root)
    canary = "Cv" + secrets.token_urlsafe(30).replace("-", "x").replace("_", "y")
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


def _hooks(home: str) -> dict:
    command = f"env BLINDFOLD_HOME={home} BLINDFOLD_CONFIG={home}/config.json {LAUNCHER} hook"
    entry = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
    return {"hooks": {"PreToolUse": [{"matcher": ".*", **entry}], "PostToolUse": [{"matcher": ".*", **entry}]}}


def _run(argv: List[str], cwd: str) -> Tuple[int, str]:
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return 127, f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return proc.returncode, proc.stdout + proc.stderr


def _claude(work: str, home: str) -> Tuple[int, str, Optional[str]]:
    settings = os.path.join(home, "claude-settings.json")
    # A real allow-list rather than blanket Bash permission, so the run also
    # proves the wrapped commands still match the user's rules.
    with open(settings, "w") as handle:
        json.dump({**_hooks(home), "permissions": {"allow": ["Read", "Bash(cat:*)", "Bash(set:*)"], "deny": ["Bash(rm:*)"]}}, handle)
    code, out = _run(["claude", "-p", PROMPT, "--settings", settings, "--output-format", "json"], work)
    transcript = None
    try:
        session = json.loads(out.strip().splitlines()[-1]).get("session_id")
        found = glob.glob(os.path.expanduser(f"~/.claude/projects/*/{session}.jsonl")) if session else []
        transcript = found[0] if found else None
    except (ValueError, IndexError, AttributeError):
        pass
    return code, out, transcript


def _grok(work: str, home: str) -> Tuple[int, str, Optional[str]]:
    hooks_dir = os.path.join(work, ".grok", "hooks")
    os.makedirs(hooks_dir)
    with open(os.path.join(hooks_dir, "blindfold.json"), "w") as handle:
        json.dump(_hooks(home), handle)
    code, out = _run(["grok", "-p", PROMPT, "--cwd", work, "--trust", "--yolo", "--max-turns", "8"], work)
    return code, out, None


AGENTS = {"claude": _claude, "grok": _grok}


def run_agent(name: str) -> bool:
    work, home, canary = _workspace()
    try:
        code, out, transcript = AGENTS[name](work, home)
        saw_placeholder = out.count("<blindfold kind=") >= 4
        leaked = canary in out
        transcript_leak = bool(transcript) and canary in _read(transcript)
        # Claude: the user's deny rule must still apply to the wrapped command.
        deny_held = name != "claude" or os.path.exists(os.path.join(work, "keep.txt"))
        ok = code == 0 and saw_placeholder and not leaked and not transcript_leak and deny_held
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
        print(f"  exit code {code}; placeholder seen: {saw_placeholder}; canary in reply: {leaked}")
        if name == "claude":
            print(f"  transcript: {transcript or 'not found'}; canary in transcript: {transcript_leak}; deny rule held: {deny_held}")
        if not ok:
            print("  output (canary redacted):\n    " + out.replace(canary, "<CANARY>")[-1500:].replace("\n", "\n    "))
        return ok
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(agents: Optional[List[str]] = None) -> int:
    """In-process checks always; real agents when named."""
    from .runtime import build_runtime
    from .config import Config

    rt = build_runtime(Config(use_default_known_secret_files=False), environ={})
    fake = "sk_" + "live_" + secrets.token_hex(20)
    masked, findings = rt.masker.mask(f"STRIPE_SECRET_KEY={fake}")
    unit_ok = fake not in masked and bool(findings)
    print(f"engine: {'PASS' if unit_ok else 'FAIL'}")
    results = [unit_ok] + [run_agent(name) for name in (agents or [])]
    return 0 if all(results) else 1
