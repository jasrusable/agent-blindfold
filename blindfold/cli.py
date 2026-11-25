"""Command line: blindfold hook | scan | doctor | install | env-set | selftest."""

import argparse
import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .config import CONFIG_DIR, CONFIG_PATH, KEY_PATH, load_config
from .cli_paths import LAUNCHER, SKILL_DIR
from .hook import main as hook_main
from .runtime import load_runtime

EVENTS = {
    "SessionStart": None,
    "UserPromptSubmit": None,
    "PreToolUse": ".*",
    "PostToolUse": ".*",
    "PostToolUseFailure": ".*",
    "PostToolBatch": None,
    "Stop": None,
}
# Events whose hook failure must block (refuse the call, block the prompt, stop
# the turn) rather than let the action go ahead. Claude Code honours
# onFailure on all of them (2.1.295+); Grok only on PreToolUse and
# UserPromptSubmit, and ignores PostToolBatch.
FAIL_CLOSED_EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch")
# Well over blindfold's own 22s deadline, so the agent's timeout never decides.
HOOK_TIMEOUT = 60
MIN_CLAUDE = (2, 1, 295)
STATE_PATH = os.path.join(CONFIG_DIR, "install-state.json")
TARGETS = {
    "claude": os.path.expanduser("~/.claude/settings.json"),
    "grok": os.path.expanduser("~/.grok/hooks/blindfold.json"),
}
SKILL_TARGETS = {"claude": os.path.expanduser("~/.claude/skills/blindfold"), "grok": os.path.expanduser("~/.grok/skills/blindfold")}


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def cmd_scan(args) -> int:
    masker = load_runtime().masker
    text = _read(args.file) if args.file else sys.stdin.read()
    masked, findings = masker.mask(text)
    sys.stdout.write(masked)
    if findings:
        kinds = sorted({f.kind for f in findings})
        print(f"\nblindfold: masked {len(findings)} ({', '.join(kinds)})", file=sys.stderr)
    return 0


def installed_hooks() -> Dict[str, Optional[str]]:
    """Per agent, the blindfold command its real config runs, or None. Grok also
    runs the hooks in ~/.claude/settings.json (Claude compatibility)."""
    found = {}
    for agent, path in TARGETS.items():
        match = re.search(r"([^\s\"']*blindfold)(?: [^\s\"']+){0,4} hook", _read(path)) if os.path.exists(path) else None
        found[agent] = match.group(1) if match else None
    found["grok"] = found["grok"] or found["claude"]
    return found


def cmd_doctor(_args) -> int:
    started = time.monotonic()
    rt = load_runtime()
    elapsed = 1000 * (time.monotonic() - started)
    masker, known, sources = rt.masker, rt.known, rt.known.sources
    print(f"blindfold {__version__}")
    if rt.warning:
        print(f"⚠️  {rt.warning}")
    print(f"config:  {CONFIG_PATH} ({'present' if os.path.exists(CONFIG_PATH) else 'defaults'})")
    print(f"key:     {KEY_PATH} ({'present' if os.path.exists(KEY_PATH) else 'created on first use'})")
    print(f"sources: {len(sources)} file(s) matched")
    for path in sources:
        print(f"  {path}")
    for path, problem in known.problems:
        print(f"  ⚠️  NOT USED: {path}: {problem} (its secrets are not masked by exact match)")
    print(f"known:   {masker.known_count} masked value(s), including encodings (values never shown)")
    print(f"load:    {elapsed:.0f} ms")
    installed = installed_hooks()
    print(f"claude : hooks {'installed' if installed['claude'] else 'not installed'} ({TARGETS['claude']})")
    own_grok = os.path.exists(TARGETS["grok"]) and "blindfold" in _read(TARGETS["grok"])
    grok = "installed" if own_grok else "via ~/.claude/settings.json" if installed["grok"] else "not installed"
    print(f"grok   : hooks {grok}")
    status = 0
    if installed["claude"]:
        problems = hook_problems(json.loads(_read(TARGETS["claude"])))
        version = claude_version()
        if version is not None and version < MIN_CLAUDE:
            problems.append(f"Claude Code {'.'.join(map(str, version))} is older than 2.1.295, which ignores onFailure")
        print(f"fail-closed: {'ok' if not problems else 'NOT fail-closed'}" + (f" (Claude Code {'.'.join(map(str, version))})" if version else ""))
        for problem in problems:
            print(f"  ⚠️  {problem}")
        status = 1 if problems else 0
        from .guards import claude_deny_rules

        deny = json.loads(_read(TARGETS["claude"])).get("permissions", {}).get("deny", [])
        missing = [rule for rule in claude_deny_rules(rt.config) if rule not in deny]
        print(f"deny rules: {'ok' if not missing else f'{len(missing)} missing; run `blindfold install --apply`'}")
    print("grok   : fails closed before calls and prompts; a failed masking hook after a call fails open in Grok")
    return status


def hook_command() -> str:
    """The hook command: an absolute interpreter and launcher, so it runs the
    same whatever PATH the agent was started with."""
    python = sys.executable if sys.executable and os.path.isabs(sys.executable) else "/usr/bin/python3"
    return f"{shlex.quote(python)} {shlex.quote(LAUNCHER)} hook"


def _hook_entries(command: str) -> Dict[str, List[Dict[str, Any]]]:
    entries = {}
    for event, matcher in EVENTS.items():
        handler: Dict[str, Any] = {"type": "command", "command": command, "timeout": HOOK_TIMEOUT}
        if event in FAIL_CLOSED_EVENTS:
            handler["onFailure"] = "block"
        group: Dict[str, Any] = {"matcher": matcher} if matcher else {}
        group["hooks"] = [handler]
        entries[event] = [group]
    return entries


def _read_state() -> Dict[str, Any]:
    try:
        state = json.loads(_read(STATE_PATH))
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _with_deny_rules(settings: Dict[str, Any], rules: List[str], owned: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """settings with blindfold's deny rules, and the rules blindfold now owns.
    A rule the user already had is left theirs, so uninstalling never drops it."""
    permissions = dict(settings.get("permissions") or {})
    current = [rule for rule in permissions.get("deny", []) if rule not in owned or rule in rules]
    added = [rule for rule in rules if rule not in current]
    still_owned = [rule for rule in owned if rule in rules]
    permissions["deny"] = current + added
    return {**settings, "permissions": permissions}, still_owned + added


def _with_blindfold(settings: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(settings.get("hooks", {}))
    for event, groups in _hook_entries(command).items():
        kept = [g for g in hooks.get(event, []) if not any("blindfold" in h.get("command", "") for h in g.get("hooks", []))]
        hooks[event] = kept + groups
    return {**settings, "hooks": hooks}


def _write_json(path: str, value: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def cmd_install(args) -> int:
    from .guards import claude_deny_rules

    command = hook_command()
    agents = args.agents or ["claude"]
    state = _read_state()
    for agent in agents:
        path = TARGETS[agent]
        current = json.loads(_read(path)) if os.path.exists(path) else {}
        if agent == "claude":
            updated, owned = _with_deny_rules(_with_blindfold(current, command), claude_deny_rules(load_config()), state.get("deny", []))
        else:
            updated, owned = {"hooks": _hook_entries(command)}, None
        before = json.dumps(current, indent=2).splitlines()
        after = json.dumps(updated, indent=2).splitlines()
        diff = list(difflib.unified_diff(before, after, path, path + " (with blindfold)", lineterm=""))
        print("\n".join(diff) if diff else f"{path}: already up to date")
        if args.apply and diff:
            if os.path.exists(path):
                backup = f"{path}.bak-blindfold-{int(time.time())}"
                shutil.copy2(path, backup)
                print(f"backup: {backup}")
            _write_json(path, updated)
            print(f"wrote {path}")
        if args.apply and owned is not None and owned != state.get("deny"):
            state["deny"] = owned
            _write_json(STATE_PATH, state)
        skill = SKILL_TARGETS[agent]
        if args.apply and not os.path.exists(skill):
            os.makedirs(os.path.dirname(skill), exist_ok=True)
            os.symlink(SKILL_DIR, skill)
            print(f"linked skill: {skill} -> {SKILL_DIR}")
    if not args.apply:
        print("\nDry run. Re-run with --apply to write (a backup is kept).")
    if "grok" in agents and "claude" in agents:
        print("Note: Grok also loads ~/.claude/settings.json, so installing both runs blindfold twice in Grok.")
    return 0


def _version(text: str) -> Optional[Tuple[int, ...]]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(part) for part in match.groups()) if match else None


def claude_version() -> Optional[Tuple[int, ...]]:
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return _version(out)


def hook_problems(settings: Dict[str, Any]) -> List[str]:
    """What keeps blindfold's hooks in a Claude settings object from failing closed."""
    problems = []
    hooks = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {}
    for event in EVENTS:
        handlers = [
            h for g in hooks.get(event, []) if isinstance(g, dict) for h in g.get("hooks", [])
            if isinstance(h, dict) and "blindfold" in str(h.get("command", ""))
        ]
        if not handlers:
            problems.append(f"{event}: no blindfold hook")
            continue
        for handler in handlers:
            if event in FAIL_CLOSED_EVENTS and handler.get("onFailure") != "block":
                problems.append(f"{event}: hook doesn't set \"onFailure\": \"block\", so a hook failure fails open")
            words = shlex.split(str(handler.get("command", "")))
            program = words[0] if words else ""
            if os.path.basename(program) == "blindfold":
                problems.append(f"{event}: hook runs the launcher through its `#!/usr/bin/env python3` line, which needs python3 on PATH; reinstall to use an absolute interpreter")
            elif not os.path.isabs(program):
                problems.append(f"{event}: hook starts {program!r} from PATH; reinstall to use an absolute interpreter")
            elif not os.access(program, os.X_OK):
                problems.append(f"{event}: hook interpreter {program} is missing")
            launcher = next((w for w in words if w.endswith("blindfold")), None)
            if launcher and not os.path.exists(launcher):
                problems.append(f"{event}: hook launcher {launcher} is missing")
            timeout = handler.get("timeout")
            if not isinstance(timeout, (int, float)) or timeout < 30:
                problems.append(f"{event}: hook timeout {timeout!r} leaves no margin over blindfold's 22s deadline")
    return problems


def cmd_env_set(args) -> int:
    from .envset import Refused, set_line

    try:
        print(set_line(args.file, args.key, args.value))
    except Refused as refusal:
        print(f"blindfold: refused: {refusal}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001
        # The type only: an error's text can quote the file (a decode error names a byte).
        print(f"blindfold: couldn't set {args.key} in {args.file} ({type(error).__name__})", file=sys.stderr)
        return 1
    return 0


def cmd_selftest(args) -> int:
    from .selftest import run

    return run(agents=args.agents, installed=args.installed, fail_closed=args.fail_closed)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blindfold", description="Mask secrets in AI agent tool output.")
    parser.add_argument("--version", action="version", version=f"blindfold {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("hook", help="run as a Claude Code / Grok hook (reads the event on stdin)")
    scan = sub.add_parser("scan", help="mask a file or stdin to stdout")
    scan.add_argument("file", nargs="?")
    sub.add_parser("doctor", help="show config, sources and install state (never values)")
    install = sub.add_parser("install", help="add blindfold's hooks and skill (dry run unless --apply)")
    install.add_argument("--agent", dest="agents", action="append", choices=sorted(TARGETS))
    install.add_argument("--apply", action="store_true")
    env_set = sub.add_parser(
        "env-set", help="add or replace one non-secret KEY=VALUE line in a dotenv file, without showing the file"
    )
    env_set.add_argument("file")
    env_set.add_argument("key")
    env_set.add_argument("value")
    selftest = sub.add_parser("selftest", help="canary tests; --agent runs them through a real agent")
    selftest.add_argument("--agent", dest="agents", action="append", choices=sorted(TARGETS))
    selftest.add_argument(
        "--installed", action="store_true", help="test the hooks the agents' own config runs, not this checkout's"
    )
    selftest.add_argument(
        "--fail-closed", action="store_true",
        help="with --agent: also run real sessions with a hook that can't start and with PATH emptied",
    )
    args = parser.parse_args(argv)
    commands = {"hook": lambda _a: hook_main(), "scan": cmd_scan, "doctor": cmd_doctor, "install": cmd_install, "selftest": cmd_selftest, "env-set": cmd_env_set}
    if args.command is None:
        parser.print_help()
        return 2
    return commands[args.command](args)
