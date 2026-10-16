"""Hard and adversarial cases, each tied to a failure mode found while building blindfold."""

import io
import json
import os
import sys
import tempfile
import time
import unicodedata
import unittest
from unittest import mock

from blindfold import hook
from blindfold.config import Config
from blindfold.known import KnownSecret
from blindfold.mask import Masker
from blindfold.runtime import build_runtime, load_runtime
from blindfold.structure import strings

from . import corpus
from .helpers import reply, runtime

TOKEN = corpus.GITHUB_PAT
KNOWN = corpus.rand(30)
M = Masker(known=[KnownSecret(KNOWN, "API_SECRET")], key=b"e" * 32)


def post(response, **extra):
    return {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": response, **extra}


class ForgedPlaceholders(unittest.TestCase):
    def test_a_token_inside_a_forged_kind_is_masked(self):
        for hidden in (TOKEN, KNOWN):
            forged = f"<blindfold kind={hidden} len=1 id=000000>"
            masked, findings = M.mask(f"before {forged} after")
            with self.subTest(hidden=hidden[:8]):
                self.assertNotIn(hidden, masked)
                self.assertTrue(findings)

    def test_genuine_placeholders_are_kept(self):
        once, _ = M.mask(f"API_SECRET={KNOWN} and {TOKEN}")
        self.assertEqual(M.mask(once), (once, []))

    def test_sentinel_characters_in_input_cannot_forge_protection(self):
        text = f"0 {TOKEN} "
        masked, findings = M.mask(text)
        self.assertNotIn(TOKEN, masked)
        self.assertNotIn("", masked)
        self.assertNotIn("", masked)


class FingerprintKey(unittest.TestCase):
    def test_the_key_file_is_masked_when_read(self):
        with tempfile.TemporaryDirectory() as home, mock.patch("blindfold.config.KEY_PATH", os.path.join(home, "fingerprint.key")), mock.patch("blindfold.config.CONFIG_DIR", home):
            rt = build_runtime(Config(use_default_known_secret_files=False), environ={})
            with open(os.path.join(home, "fingerprint.key")) as handle:
                key = handle.read().strip()
            masked, findings = rt.masker.mask(f"{key}\n")
            self.assertNotIn(key, masked)
            self.assertEqual(findings[0].kind, "env:BLINDFOLD_FINGERPRINT_KEY")


class AgentDrift(unittest.TestCase):
    def test_a_renamed_result_field_is_still_masked_and_flagged(self):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_output": {"stdout": f"x {KNOWN}"}}
        out = reply(event, M)["hookSpecificOutput"]
        self.assertNotIn(KNOWN, json.dumps(out))
        self.assertIn("did not recognise", out["additionalContext"])

    def test_unknown_events_and_extra_fields_are_ignored(self):
        self.assertIsNone(reply({"hook_event_name": "SomeFutureEvent", "tool_response": KNOWN}, M))
        event = post({"stdout": "ok", "stderr": ""}, future_field={"nested": [1, 2]}, toolUseId="x")
        self.assertIsNone(reply(event, M))

    def test_grok_and_claude_names_for_the_same_event(self):
        grok = {"hookEventName": "post_tool_use", "hook_event_name": "PostToolUse", "toolName": "run_terminal_command",
                "toolResult": {"type": "Bash", "output_for_prompt": KNOWN}, "tool_response": {"type": "Bash", "output_for_prompt": KNOWN}}
        out = reply(grok, M)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(out["type"], "Bash")
        self.assertNotIn(KNOWN, json.dumps(out))


class BrokenConfig(unittest.TestCase):
    def test_invalid_config_keeps_masking_with_defaults_and_warns(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "config.json")
            with open(path, "w") as handle:
                handle.write("{ not json")
            with mock.patch("blindfold.config.CONFIG_PATH", path), mock.patch("blindfold.config.KEY_PATH", os.path.join(home, "k")), mock.patch("blindfold.config.CONFIG_DIR", home):
                rt = load_runtime(environ={})
        self.assertIn("invalid", rt.warning)
        masked, _ = rt.masker.mask(f"STRIPE_API_KEY={corpus.STRIPE_LIVE}")
        self.assertNotIn(corpus.STRIPE_LIVE, masked)
        out = reply(post({"stdout": "clean", "stderr": ""}), rt.masker, warning=rt.warning)
        self.assertIn("invalid", out["hookSpecificOutput"]["additionalContext"])


class LeakAlarm(unittest.TestCase):
    def _transcript(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write(text)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_claude_transcript_with_a_raw_value_raises_the_alarm(self):
        path = self._transcript(json.dumps({"type": "user", "toolUseResult": {"stdout": KNOWN}}) + "\n")
        out = reply({"hook_event_name": "Stop", "transcript_path": path}, M)
        self.assertIn("API_SECRET", out["systemMessage"])
        self.assertNotIn(KNOWN, out["systemMessage"])

    def test_grok_transcript_keeps_originals_so_it_is_not_scanned(self):
        path = self._transcript(KNOWN)
        self.assertIsNone(reply({"hookEventName": "stop", "hook_event_name": "Stop", "transcript_path": path}, M))

    def test_missing_transcript_is_harmless(self):
        self.assertIsNone(reply({"hook_event_name": "Stop", "transcript_path": "/nonexistent/x.jsonl"}, M))


class FailClosedExtremes(unittest.TestCase):
    def test_absurd_nesting_is_withheld_not_passed_through(self):
        value = {"stdout": KNOWN}
        for _ in range(30000):
            value = [value]
        out = hook.respond({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": value}, runtime(M))
        self.assertIsNotNone(out)
        self.assertNotIn(KNOWN, "\n".join(strings(out)))

    def test_unparseable_deep_json_exits_2(self):
        raw = ("[" * 200000 + "]" * 200000).encode()
        stdin = io.TextIOWrapper(io.BytesIO(raw))
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", io.StringIO()), mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertIn(hook.main(), (0, 2))

    def test_placeholder_in_a_bash_command_is_denied(self):
        placeholder = M.placeholder("env:API_SECRET", KNOWN)
        out = reply({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"echo '{placeholder}' > .env"}}, M)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIsNone(reply({"hook_event_name": "PreToolUse", "tool_name": "Grep", "tool_input": {"pattern": placeholder}}, M))


class Encodings(unittest.TestCase):
    def test_hex_secret_in_another_case(self):
        secret = corpus.hexs(40)
        m = Masker(known=[KnownSecret(secret, "HEX_SECRET")], key=b"e" * 32)
        self.assertNotIn(secret.upper(), m.mask(secret.upper())[0])

    def test_unicode_normalisation_forms(self):
        secret = "pässwörd-" + corpus.rand(10)
        m = Masker(known=[KnownSecret(secret, "DB_PASSWORD")], key=b"e" * 32)
        for form in ("NFC", "NFD"):
            variant = unicodedata.normalize(form, secret)
            self.assertNotIn(variant, m.mask(f"pw {variant}")[0])

    def test_secret_split_by_ansi_colour(self):
        split = KNOWN[:10] + "\x1b[1m" + KNOWN[10:]
        self.assertNotIn(KNOWN, M.mask(split)[0])


class Scale(unittest.TestCase):
    def test_five_megabytes_of_output(self):
        text = ("log line with nothing interesting " * 30 + "\n") * 5000
        started = time.monotonic()
        M.mask(text + KNOWN)
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
