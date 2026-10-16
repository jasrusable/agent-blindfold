import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from blindfold import hook
from blindfold.events import Event
from blindfold.handlers import withheld_reply
from blindfold.structure import deep_map
from blindfold.config import Config
from blindfold.known import KnownSecret
from blindfold.mask import PLACEHOLDER_RE, Masker

from . import corpus
from .helpers import reply as hook_reply

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN = corpus.rand(40)
M = Masker(known=[KnownSecret(KNOWN, "PAYMENT_WEBHOOK_SECRET")], key=b"k" * 32)
CFG = Config(use_default_known_secret_files=False)
SECRET_LINE = f"line two STRIPE_API_KEY={corpus.STRIPE_LIVE}\n"


def run(event):
    return hook_reply(event, M)


def strings(value):
    out = []
    deep_map(value, lambda s: out.append(s) or s)
    return "\n".join(out)


# Shapes recorded from Claude Code 2.1.x (PostToolUse stdin).
CLAUDE_RESPONSES = {
    "Read": {"type": "text", "file": {"filePath": "/w/.env", "content": "line one\n" + SECRET_LINE, "numLines": 2, "startLine": 1, "totalLines": 2}},
    "Bash": {"stdout": SECRET_LINE, "stderr": f"warn {KNOWN}", "interrupted": False, "isImage": False, "noOutputExpected": False},
    "Grep": {"mode": "content", "content": "a.env:2:" + SECRET_LINE, "filenames": ["a.env"], "numFiles": 1, "numLines": 1},
    "Glob": {"filenames": ["/w/a.env"], "durationMs": 3, "numFiles": 1, "truncated": False},
    "Edit": {"filePath": "/w/a.env", "oldString": "x", "newString": "y", "originalFile": SECRET_LINE, "structuredPatch": [{"lines": ["-" + SECRET_LINE]}], "userModified": False, "replaceAll": False},
    "mcp__linear__get_issue": [{"type": "text", "text": f"token {KNOWN}"}],
}


class PostToolUseClaude(unittest.TestCase):
    def test_every_shape_is_masked_in_place(self):
        for tool, response in CLAUDE_RESPONSES.items():
            event = {"hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": {}, "tool_response": response}
            reply = run(event)
            with self.subTest(tool=tool):
                if tool == "Glob":
                    self.assertIsNone(reply, "nothing secret in a file list: emit nothing")
                    continue
                out = reply["hookSpecificOutput"]
                self.assertEqual(out["hookEventName"], "PostToolUse")
                masked = out["updatedToolOutput"]
                self.assertEqual(type(masked), type(response), "Claude ignores a replacement of another shape")
                if isinstance(response, dict):
                    self.assertEqual(set(masked), set(response), "every key must survive")
                text = strings(masked)
                self.assertNotIn(corpus.STRIPE_LIVE, text)
                self.assertNotIn(KNOWN, text)
                self.assertRegex(text, PLACEHOLDER_RE)
                self.assertIn("blindfold masked", out["additionalContext"])

    def test_non_strings_are_untouched(self):
        response = CLAUDE_RESPONSES["Read"]
        masked = run({"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": response})["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(masked["file"]["numLines"], 2)
        self.assertEqual(masked["file"]["totalLines"], 2)

    def test_clean_output_emits_nothing(self):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": "hello\n", "stderr": ""}}
        self.assertIsNone(run(event))

    def test_image_payload_is_skipped(self):
        image = {"type": "image", "file": {"base64": corpus.png_base64(), "type": "image/png"}}
        self.assertIsNone(run({"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": image}))

    def test_claude_failure_raises_the_alarm_instead_of_a_replacement_it_would_ignore(self):
        reply = run({"hook_event_name": "PostToolUseFailure", "tool_name": "mcp__x__y", "error": f"failed with {KNOWN}"})
        self.assertIn("Rotate", reply["systemMessage"])
        self.assertNotIn("updatedToolOutput", reply["hookSpecificOutput"])
        self.assertEqual(reply["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        self.assertNotIn(KNOWN, json.dumps(reply))

    def test_grok_failure_error_text_is_masked(self):
        reply = run({"hookEventName": "post_tool_use_failure", "hook_event_name": "PostToolUseFailure", "tool_name": "x", "error": f"failed with {KNOWN}"})
        self.assertNotIn(KNOWN, reply["hookSpecificOutput"]["updatedToolOutput"])


class PostToolUseGrok(unittest.TestCase):
    def test_typed_result_is_edited_in_place(self):
        result = {"type": "Bash", "command": "cat .env", "exit_code": 0, "output_for_prompt": SECRET_LINE}
        event = {"hookEventName": "post_tool_use", "hook_event_name": "PostToolUse", "toolName": "run_terminal_command", "toolResult": result}
        masked = run(event)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(masked["type"], "Bash")
        self.assertEqual(masked["exit_code"], 0)
        self.assertNotIn(corpus.STRIPE_LIVE, masked["output_for_prompt"])

    def test_truncated_result_string_is_masked(self):
        event = {"hook_event_name": "PostToolUse", "toolName": "read_file", "toolResult": "x" * 10 + SECRET_LINE, "toolResultTruncated": True}
        masked = run(event)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertIsInstance(masked, str)
        self.assertNotIn(corpus.STRIPE_LIVE, masked)


class FailClosed(unittest.TestCase):
    def test_masker_crash_withholds_everything(self):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": SECRET_LINE, "stderr": "", "interrupted": False}}
        reply = withheld_reply(Event(event))
        masked = reply["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(masked), {"stdout", "stderr", "interrupted"})
        self.assertNotIn(corpus.STRIPE_LIVE, strings(masked))
        self.assertIs(masked["interrupted"], False)

    def test_main_never_crashes_and_never_echoes_the_original(self):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": SECRET_LINE, "stderr": ""}}
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(event).encode()))
        stdout = io.StringIO()
        with mock.patch("blindfold.hook.handle", side_effect=RuntimeError("boom")), mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout):
            self.assertEqual(hook.main(), 0)
        reply = json.loads(stdout.getvalue())
        self.assertNotIn(corpus.STRIPE_LIVE, json.dumps(reply))
        self.assertIn("withheld", json.dumps(reply))

    def test_pre_tool_use_crash_allows_the_call_and_says_so(self):
        # The output is still masked (or withheld) afterwards; refusing every
        # call over a bug would lock the user and every agent out.
        reply = withheld_reply(Event({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}))
        self.assertNotIn("permissionDecision", reply["hookSpecificOutput"])
        self.assertIn("doctor", reply["hookSpecificOutput"]["additionalContext"])

    def test_prompt_check_crash_warns_instead_of_blocking(self):
        reply = withheld_reply(Event({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}))
        self.assertNotIn("decision", reply)
        self.assertIn("unchecked", reply["systemMessage"])

    def test_unreadable_input_blocks_with_exit_2(self):
        stdin = io.TextIOWrapper(io.BytesIO(b"\xff not json"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
            self.assertEqual(hook.main(), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("blocked", stderr.getvalue())

    def test_keys_holding_secrets_are_masked_but_schema_keys_kept(self):
        response = [{"type": "text", "text": "ok"}, {corpus.STRIPE_LIVE: {"note": "keyed by a token"}}]
        masked = run({"hook_event_name": "PostToolUse", "tool_name": "mcp__x__y", "tool_response": response})["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(masked[0], {"type": "text", "text": "ok"})
        self.assertNotIn(corpus.STRIPE_LIVE, json.dumps(masked))


class Guards(unittest.TestCase):
    def test_write_with_placeholder_is_denied(self):
        placeholder = M.placeholder("env:STRIPE_API_KEY", corpus.STRIPE_LIVE)
        for tool, tool_input in [
            ("Write", {"file_path": "/w/.env", "content": f"STRIPE_API_KEY={placeholder}\n"}),
            ("Edit", {"file_path": "/w/.env", "old_string": "a", "new_string": placeholder}),
            ("MultiEdit", {"file_path": "/w/.env", "edits": [{"old_string": "a", "new_string": placeholder}]}),
            ("search_replace", {"path": "/w/.env", "new_string": placeholder}),
        ]:
            with self.subTest(tool=tool):
                reply = run({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input})
                self.assertEqual(reply["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_docs_mentioning_the_format_are_allowed(self):
        doc = "Placeholders look like <blindfold kind=env:NAME len=107 id=xxxxxx>."
        self.assertIsNone(run({"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "/w/README.md", "content": doc}}))

    def test_known_value_in_a_command_is_denied(self):
        reply = run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"curl -d token={KNOWN} x"}})
        self.assertEqual(reply["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("PAYMENT_WEBHOOK_SECRET", reply["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertNotIn(KNOWN, json.dumps(reply))

    def test_ordinary_calls_pass(self):
        for tool, tool_input in [("Read", {"file_path": "/w/.env"}), ("Write", {"file_path": "/w/a.ts", "content": "const x = 1"})]:
            with self.subTest(tool=tool):
                self.assertIsNone(run({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}))

    def test_claude_bash_is_wrapped_to_exit_zero_and_grok_is_not(self):
        claude = run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "npm test", "timeout": 5}})
        updated = claude["hookSpecificOutput"]["updatedInput"]
        self.assertEqual(updated["timeout"], 5, "other input fields survive")
        self.assertIn("npm test", updated["command"])
        self.assertNotIn("permissionDecision", claude["hookSpecificOutput"], "the user's permission flow still decides")
        grok = {"hookEventName": "pre_tool_use", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "npm test"}}
        self.assertIsNone(run(grok))


class Alarms(unittest.TestCase):
    def test_prompt_with_known_secret_is_blocked(self):
        reply = run({"hook_event_name": "UserPromptSubmit", "prompt": f"use this key {KNOWN} please"})
        self.assertEqual(reply["decision"], "block")
        self.assertIn("PAYMENT_WEBHOOK_SECRET", reply["reason"])
        self.assertNotIn(KNOWN, reply["reason"])

    def test_clean_prompt_passes(self):
        self.assertIsNone(run({"hook_event_name": "UserPromptSubmit", "prompt": "deploy to staging"}))

    def test_stop_warns_when_reply_leaks(self):
        reply = run({"hook_event_name": "Stop", "last_assistant_message": f"the key is {KNOWN}"})
        self.assertIn("rotate", reply["systemMessage"].lower())
        self.assertNotIn(KNOWN, reply["systemMessage"])
        self.assertIsNone(run({"hook_event_name": "Stop", "last_assistant_message": "all done"}))

    def test_session_start_note(self):
        note = run({"hook_event_name": "SessionStart"})["hookSpecificOutput"]["additionalContext"]
        for must in ("<blindfold kind=", "SECRET EXPOSED", "allow_ids", "Never try to recover"):
            self.assertIn(must, note)


class SkillContract(unittest.TestCase):
    def test_description_fits_the_skill_spec(self):
        with open(os.path.join(REPO, "skill", "blindfold", "SKILL.md"), encoding="utf-8") as handle:
            text = handle.read()
        description = text.split("description:", 1)[1].split("\n---", 1)[0].strip().strip('"')
        self.assertLessEqual(len(description), 1024, f"description is {len(description)} chars")
        for must in ("<blindfold kind=", "SECRET EXPOSED", "allow_ids", "only the user can change"):
            self.assertIn(must, description)


class EndToEndProcess(unittest.TestCase):
    """Run the real launcher as an agent would, with known secrets from a temp file."""

    def test_launcher_masks_a_known_value_from_a_dotenv(self):
        with tempfile.TemporaryDirectory() as home:
            secret = corpus.rand(36)
            env_file = os.path.join(home, "app.env")
            with open(env_file, "w") as handle:
                handle.write(f"PAYMENT_PROVIDER_SECRET={secret}\n")
            with open(os.path.join(home, "config.json"), "w") as handle:
                json.dump({"extra_known_secret_files": [env_file], "use_default_known_secret_files": False}, handle)
            event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": f"value={secret}", "stderr": ""}}
            env = {**os.environ, "BLINDFOLD_HOME": home, "BLINDFOLD_CONFIG": os.path.join(home, "config.json")}
            proc = subprocess.run([os.path.join(REPO, "bin", "blindfold"), "hook"], input=json.dumps(event), capture_output=True, text=True, env=env, timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            reply = json.loads(proc.stdout)
            self.assertNotIn(secret, proc.stdout)
            self.assertIn("env:PAYMENT_PROVIDER_SECRET", reply["hookSpecificOutput"]["updatedToolOutput"]["stdout"])
            self.assertEqual(oct(os.stat(os.path.join(home, "fingerprint.key")).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
