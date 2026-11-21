"""Fail-closed behaviour and the rules folded in from the old stray hooks."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from blindfold import batch, cli, guards, hook
from blindfold.config import Config
from blindfold.events import Event
from blindfold.known import KnownSecret, parse_env_text
from blindfold.mask import Masker

from . import corpus
from .helpers import reply, runtime

M = Masker(known=[], key=b"k" * 32)
CFG = Config(use_default_known_secret_files=False)
LAUNCHER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "blindfold")
OP = "o" + "p"


def pre(command=None, cfg=CFG, cwd="/work", **tool_input):
    if command is not None:
        tool_input["command"] = command
    tool = "Bash" if command is not None else "Read"
    return reply({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": cwd}, M, cfg)


def denied(out):
    return bool(out) and out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


class EnvDumps(unittest.TestCase):
    def test_whole_environment_dumps_are_refused(self):
        for command in (
            "printenv", "printenv HOME", "env", "env | sort", "env > /tmp/e", "set", "set | grep X", "export -p",
            "declare -p", "declare -px", "typeset -p NAME", "export", "direnv export bash", "direnv show", "direnv dump",
            "direnv exec . make", "sudo printenv", "FOO=1 env", "true && env", "cat /proc/self/environ",
            "bash -c 'printenv'",
        ):
            self.assertTrue(denied(pre(command)), command)

    def test_ordinary_uses_pass(self):
        for command in (
            "env FOO=1 make", "set -euo pipefail; make", "export FOO=bar", "declare -a list", "direnv allow",
            "direnv status", "compgen -v", "git commit -m 'drop printenv from the docs'", "echo env", "ls environment",
        ):
            self.assertFalse(denied(pre(command)), command)

    def test_credential_variables_are_not_printed(self):
        for command in ('echo "$DATABASE_URL"', "echo $PGPASSWORD", 'printf "%s" "${STRIPE_SECRET_KEY}"', "echo $GITHUB_TOKEN | pbcopy"):
            self.assertTrue(denied(pre(command)), command)
        for command in ('echo ${#DATABASE_URL}', 'test -n "${DATABASE_URL:+set}" && echo set', "echo $HOME", "echo DATABASE_URL"):
            self.assertFalse(denied(pre(command)), command)

    def test_password_helpers_are_refused(self):
        for command in ("restic-password", "~/bin/restic-password | wc -c", "RESTIC_REPOSITORY=x restic-password"):
            self.assertTrue(denied(pre(command)), command)
        self.assertFalse(denied(pre("restic snapshots --password-command restic-password-helper-docs")))

    def test_the_switch_turns_them_off(self):
        self.assertFalse(denied(pre("printenv", Config(use_default_known_secret_files=False, block_env_dumps=False))))


class ProtectedFiles(unittest.TestCase):
    def test_file_tools_are_refused(self):
        home = os.path.expanduser("~")
        for path in (".envrc", "/r/app/.envrc.local", f"{home}/.config/finwise/agent.env", "~/.config/x/.env", "/k/AuthKey_ABC.p8", "~/.netrc"):
            self.assertTrue(denied(pre(file_path=path)), path)
            self.assertTrue(denied(reply({"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {"file_path": path}}, M, CFG)), path)

    def test_templates_and_ordinary_files_pass(self):
        for path in (".envrc.example", "/r/app/.env", "/r/app/README.md", "/r/.envrc.sample", "~/.config/x/settings.json"):
            self.assertFalse(denied(pre(file_path=path)), path)

    def test_commands_naming_them_are_refused(self):
        for command in ("cat .envrc", "source ./.envrc", "grep KEY ~/.config/finwise/agent.env", "cp AuthKey_X.p8 /tmp/",
                        "less $HOME/.netrc", "bash <<EOF\ncat .envrc\nEOF"):
            self.assertTrue(denied(pre(command)), command)

    def test_commands_that_only_name_them_or_write_them_down_pass(self):
        for command in ("ls -la .envrc", "test -f .envrc && echo yes", "direnv allow", "git commit -m 'ignore .envrc'",
                        "cat > notes.md <<EOF\nnever cat .envrc\nEOF"):
            self.assertFalse(denied(pre(command)), command)

    def test_extra_patterns(self):
        cfg = Config(use_default_known_secret_files=False, extra_protected_files=["finwise-*-*.json", "~/projects/FinWise/.env*"])
        self.assertTrue(denied(pre(file_path="/d/finwise-123-abc.json", cfg=cfg)))
        self.assertTrue(denied(pre(file_path="~/projects/FinWise/.env.local", cfg=cfg)))
        self.assertFalse(denied(pre(file_path="~/projects/FinWise/.env.example", cfg=cfg)))
        self.assertFalse(denied(pre(file_path=".envrc", cfg=Config(use_default_known_secret_files=False, protect_secret_files=False))))

    def test_envrc_values_are_known_secrets(self):
        found = parse_env_text("export DATABASE_URL=postgres://u:longpassword@h/db\n", 8)
        self.assertEqual([secret.name for secret in found], ["DATABASE_URL"])
        from blindfold.config import DEFAULT_SOURCES
        self.assertTrue(any(source.endswith("/.envrc") for source in DEFAULT_SOURCES))

    def test_deny_rules_cover_them(self):
        rules = guards.claude_deny_rules(CFG)
        for rule in ("Read(**/.envrc)", "Edit(**/.envrc)", "Read(~/.config/*/*.env)", "Read(**/*.p8)", "Read(**/.netrc)"):
            self.assertIn(rule, rules)
        self.assertIn("Read(//abs/x.json)", guards.claude_deny_rules(Config(protect_secret_files=False, extra_protected_files=["/abs/x.json"])))


class ScanBypass(unittest.TestCase):
    def test_bypasses_are_refused(self):
        for command in (
            "git commit --no-verify -m x", "git commit -n -m x", "git commit -nm x", "git commit -anm x", "git push --no-verify",
            "git -c core.hooksPath=/dev/null commit -m x", "git config core.hooksPath /tmp/none", "git config --unset core.hooksPath",
            "HUSKY=0 git commit -m x", "export HUSKY=0",
        ):
            self.assertTrue(denied(pre(command)), command)

    def test_ordinary_commits_pass(self):
        for command in (
            "git commit -m 'never use --no-verify'", "git commit -m -n", "git commit -mn", "git commit -am x",
            "git config core.hooksPath", "git config --get core.hooksPath", "git config core.hooksPath .husky",
            "git log -n 3", "cat > a.md <<EOF\ngit commit --no-verify\nEOF",
        ):
            self.assertFalse(denied(pre(command)), command)


class Batch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patch = mock.patch.object(batch, "STATE_DIR", self.tmp.name)
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def post(self, call_id, output, name="PostToolUse"):
        raw = {"hook_event_name": name, "session_id": "s1", "tool_use_id": call_id, "tool_name": "Bash",
               "tool_response": {"stdout": output, "stderr": ""}}
        return reply(raw, M, CFG)

    def run_batch(self, *calls):
        raw = {"hook_event_name": "PostToolBatch", "session_id": "s1",
               "tool_calls": [{"tool_name": "Bash", "tool_use_id": cid, "tool_response": out} for cid, out in calls]}
        return reply(raw, M, CFG)

    def test_handled_calls_pass(self):
        self.post("t1", f"key {corpus.STRIPE_LIVE}")
        self.post("t2", "clean")
        self.assertIsNone(self.run_batch(("t1", f"key {corpus.STRIPE_LIVE}"), ("t2", "clean")))

    def test_an_unhandled_call_with_a_secret_stops_the_turn(self):
        self.post("t1", "clean")
        out = self.run_batch(("t1", "clean"), ("t2", f"key {corpus.STRIPE_LIVE}"))
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(corpus.STRIPE_LIVE, json.dumps(out))

    def test_an_unhandled_clean_call_passes(self):
        self.assertIsNone(self.run_batch(("t9", "nothing secret here")))

    def test_an_unmaskable_failure_stops_the_turn(self):
        self.post("t3", f"key {corpus.STRIPE_LIVE}", name="PostToolUseFailure")
        self.assertEqual(self.run_batch(("t3", f"key {corpus.STRIPE_LIVE}"))["decision"], "block")

    def test_records_are_used_up(self):
        self.post("t1", "clean")
        self.run_batch(("t1", "clean"))
        self.assertEqual(self.run_batch(("t1", f"x {corpus.STRIPE_LIVE}"))["decision"], "block")

    def test_a_changed_event_shape_stops_the_turn(self):
        self.assertEqual(reply({"hook_event_name": "PostToolBatch", "session_id": "s1"}, M, CFG)["decision"], "block")

    def test_grok_records_nothing(self):
        reply({"hook_event_name": "PostToolUse", "hookEventName": "post_tool_use", "session_id": "s1", "tool_use_id": "g1",
               "toolName": "read_file", "toolResult": "clean"}, M, CFG)
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_stale_sessions_are_pruned(self):
        self.post("t1", "clean")
        batch.prune(now=4e12)
        self.assertEqual(os.listdir(self.tmp.name), [])


class InternalErrors(unittest.TestCase):
    def test_a_crash_refuses_blocks_and_stops(self):
        cases = (
            ({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}},
             lambda out: out["hookSpecificOutput"]["permissionDecision"] == "deny"),
            ({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, lambda out: out["decision"] == "block"),
            ({"hook_event_name": "PostToolBatch", "tool_calls": []}, lambda out: out["decision"] == "block"),
        )
        for raw, check in cases:
            with mock.patch("blindfold.hook.handle", side_effect=RuntimeError("boom")):
                self.assertTrue(check(hook.respond(raw, runtime(M))), raw)

    def test_when_the_fail_closed_reply_fails_too_the_last_resort_still_refuses(self):
        with mock.patch("blindfold.hook.handle", side_effect=RuntimeError("boom")), \
                mock.patch("blindfold.hook.withheld_reply", side_effect=RuntimeError("again")):
            out = hook.respond({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}, runtime(M))
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertEqual(hook.respond({"hook_event_name": "UserPromptSubmit"}, runtime(M))["decision"], "block")

    def test_an_invalid_config_keeps_the_default_guards(self):
        # A bad config takes the defaults (with a warning), not no checks.
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "config.json")
            with open(path, "w") as handle:
                json.dump({"no_such_key": True}, handle)
            env = {**os.environ, "BLINDFOLD_HOME": home, "BLINDFOLD_CONFIG": path}
            event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "printenv"}}
            done = subprocess.run([sys.executable, LAUNCHER, "hook"], input=json.dumps(event), capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_an_invalid_key_refuses_calls(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "fingerprint.key"), "w") as handle:
                handle.write("not a key\n")
            env = {**os.environ, "BLINDFOLD_HOME": home, "BLINDFOLD_CONFIG": os.path.join(home, "config.json")}
            event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
            done = subprocess.run([sys.executable, LAUNCHER, "hook"], input=json.dumps(event), capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


class Install(unittest.TestCase):
    def test_entries_fail_closed_with_an_absolute_interpreter(self):
        command = cli.hook_command()
        entries = cli._hook_entries(command)
        self.assertIn("PostToolBatch", entries)
        for event, groups in entries.items():
            handler = groups[0]["hooks"][0]
            self.assertEqual(handler["timeout"], 60)
            self.assertEqual(handler.get("onFailure") == "block", event in cli.FAIL_CLOSED_EVENTS, event)
        self.assertTrue(os.path.isabs(command.split()[0].strip("'")))
        self.assertEqual(cli.hook_problems({"hooks": entries}), [])

    def test_doctor_flags_entries_that_fail_open(self):
        old = {"hooks": {event: [{"hooks": [{"type": "command", "command": f"{LAUNCHER} hook", "timeout": 30}]}] for event in cli.EVENTS}}
        problems = "\n".join(cli.hook_problems(old))
        self.assertIn("onFailure", problems)
        self.assertIn("python3 on PATH", problems)
        self.assertIn("PostToolUse:", problems)
        missing = {"hooks": cli._hook_entries(f"{sys.executable} /nowhere/bin/blindfold hook")}
        self.assertIn("launcher /nowhere/bin/blindfold is missing", "\n".join(cli.hook_problems(missing)))
        self.assertIn("PostToolBatch: no blindfold hook", cli.hook_problems({"hooks": {}}))

    def test_deny_rules_are_added_once_and_only_ours_removed(self):
        settings = {"permissions": {"deny": ["Read(~/.netrc)", "Bash(rm:*)"]}}
        updated, owned = cli._with_deny_rules(settings, ["Read(~/.netrc)", "Read(**/.envrc)"], [])
        self.assertEqual(updated["permissions"]["deny"], ["Read(~/.netrc)", "Bash(rm:*)", "Read(**/.envrc)"])
        self.assertEqual(owned, ["Read(**/.envrc)"])
        again, owned_again = cli._with_deny_rules(updated, ["Read(~/.netrc)", "Read(**/.envrc)"], owned)
        self.assertEqual(again, updated)
        dropped, owned_after = cli._with_deny_rules(again, [], owned_again)
        self.assertEqual(dropped["permissions"]["deny"], ["Read(~/.netrc)", "Bash(rm:*)"])
        self.assertEqual(owned_after, [])

    def test_the_installed_command_runs_with_an_empty_path(self):
        # An agent started from a GUI or a stripped environment has no PATH to
        # find python3 with; the absolute interpreter doesn't need one.
        with tempfile.TemporaryDirectory() as home:
            event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": f"k={corpus.STRIPE_LIVE}", "stderr": ""}}
            env = {"PATH": "", "HOME": os.path.expanduser("~"), "BLINDFOLD_HOME": home, "BLINDFOLD_CONFIG": os.path.join(home, "c.json")}
            done = subprocess.run(["/bin/sh", "-c", cli.hook_command()], input=json.dumps(event), capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertNotIn(corpus.STRIPE_LIVE, done.stdout)
            self.assertIn("<blindfold kind=", done.stdout)


if __name__ == "__main__":
    unittest.main()
