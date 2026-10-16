"""Command line: blindfold hook | scan | doctor | install | selftest."""

import argparse
import difflib
import json
import os
import re
import shutil
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .config import CONFIG_PATH, KEY_PATH
from .cli_paths import LAUNCHER, SKILL_DIR
from .hook import main as hook_main
from .runtime import load_runtime

EVENTS = {
    "SessionStart": None,
    "UserPromptSubmit": None,
    "PreToolUse": ".*",
    "PostToolUse": ".*",
    "PostToolUseFailure": ".*",
    "Stop": None,
}
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
    return 0


def _hook_entries(command: str) -> Dict[str, List[Dict[str, Any]]]:
    entries = {}
    for event, matcher in EVENTS.items():
        group: Dict[str, Any] = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
        if matcher:
            group["matcher"] = matcher
        entries[event] = [group]
    return entries


def _with_blindfold(settings: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(settings.get("hooks", {}))
    for event, groups in _hook_entries(command).items():
        kept = [g for g in hooks.get(event, []) if not any("blindfold" in h.get("command", "") for h in g.get("hooks", []))]
        hooks[event] = kept + groups
    return {**settings, "hooks": hooks}


def cmd_install(args) -> int:
    command = f"{LAUNCHER} hook"
    agents = args.agents or ["claude"]
    for agent in agents:
        path = TARGETS[agent]
        current = json.loads(_read(path)) if os.path.exists(path) else {}
        updated = _with_blindfold(current, command) if agent == "claude" else {"hooks": _hook_entries(command)}
        before = json.dumps(current, indent=2).splitlines()
        after = json.dumps(updated, indent=2).splitlines()
        diff = list(difflib.unified_diff(before, after, path, path + " (with blindfold)", lineterm=""))
        print("\n".join(diff) if diff else f"{path}: already up to date")
        if args.apply and diff:
            if os.path.exists(path):
                backup = f"{path}.bak-blindfold-{int(time.time())}"
                shutil.copy2(path, backup)
                print(f"backup: {backup}")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(updated, handle, indent=2)
                handle.write("\n")
            print(f"wrote {path}")
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


def cmd_selftest(args) -> int:
    from .selftest import run

    return run(agents=args.agents, installed=args.installed)


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
    selftest = sub.add_parser("selftest", help="canary tests; --agent runs them through a real agent")
    selftest.add_argument("--agent", dest="agents", action="append", choices=sorted(TARGETS))
    selftest.add_argument(
        "--installed", action="store_true", help="test the hooks the agents' own config runs, not this checkout's"
    )
    args = parser.parse_args(argv)
    commands = {"hook": lambda _a: hook_main(), "scan": cmd_scan, "doctor": cmd_doctor, "install": cmd_install, "selftest": cmd_selftest}
    if args.command is None:
        parser.print_help()
        return 2
    return commands[args.command](args)
