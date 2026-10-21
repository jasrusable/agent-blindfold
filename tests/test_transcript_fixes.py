"""Fixes for what a review of real sessions (Oct 16-21, 2026) found: a leak
through regex-escaped values, false positives, missed failures, hook latency."""

import glob
import os
import re
import tempfile
import unittest

from blindfold.known import KnownSecret, expand_sources, parse_env_text
from blindfold.mask import Masker, trie_pattern

from . import corpus
from .helpers import reply

KEY = b"k" * 32


class RegexEscapedValues(unittest.TestCase):
    def test_a_known_value_written_as_a_regex_is_masked(self):
        value = corpus.j("https://hooks.example.com/", corpus.rand(30))
        m = Masker(known=[KnownSecret(value, "ALERT_WEBHOOK_URL")], key=KEY)
        for text in (re.escape(value), re.escape(value).replace("\\", "\\\\")):
            masked, findings = m.mask(f"allowlist = '{text}'")
            self.assertEqual([f.kind for f in findings], ["env:ALERT_WEBHOOK_URL:regex-escaped"], text)
            self.assertNotIn(value.split("/")[-1], masked)


class PublicEnvNames(unittest.TestCase):
    def test_client_bundled_values_are_not_known_secrets(self):
        value = corpus.rand(40)
        for name in ("EXPO_PUBLIC_GOOGLE_IOS_URL_SCHEME", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "STRIPE_PUBLISHABLE_KEY"):
            self.assertEqual(parse_env_text(f"{name}={value}", 8), [], name)

    def test_secret_names_still_are(self):
        value = corpus.rand(40)
        for name in ("MIXPANEL_API_SECRET", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", "PUBLIC_KEY_PASSPHRASE", "SAMPLE_API_KEY"):
            self.assertEqual([s.name for s in parse_env_text(f"{name}={value}", 8)], [name])


class Alphabets(unittest.TestCase):
    def test_distinct_characters_alone_are_not_enough(self):
        from blindfold.rules import looks_random

        self.assertTrue(looks_random("qpzry9x8gf2tvdw0s3jn54khce6mUA7L", 4.2))
        self.assertFalse(looks_random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 4.2))


class LazyKnownPattern(unittest.TestCase):
    def test_same_result_as_one_pattern_for_every_value(self):
        values = [corpus.rand(n) for n in (12, 20, 33, 64)]
        prefixed = values[0] + corpus.rand(6)
        known = [KnownSecret(v, f"SECRET_{i}") for i, v in enumerate([*values, prefixed])]
        m = Masker(known=known, key=KEY, entropy=False)
        everything = re.compile(trie_pattern([k.value for k in known]))
        for text in (f"a {values[1]} b {prefixed} c", f"{values[0]}{values[0]}", "nothing here", f"x{values[3]}y"):
            masked, _ = m.mask(text)
            self.assertEqual(masked.count("<blindfold"), len(everything.findall(text)), text)
            for value in [*values, prefixed]:
                self.assertNotIn(value, masked)

    def test_weak_values_still_match_whole_words_only(self):
        m = Masker(known=[KnownSecret("Correcthorsebattery", "DB_PASSWORD", weak=True)], key=KEY)
        self.assertEqual(len(m.mask("pw Correcthorsebattery ok")[1]), 1)
        self.assertEqual(m.mask("xCorrecthorsebatteryx")[1], [])


class ExpandSources(unittest.TestCase):
    def test_matches_what_glob_finds(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in ("a/.env", "a/.env.local", "a/.env.dev.local", "a/.env.sample", "a/b/.env", "c/x.env", "c/.hidden.env", "d/.env/f"):
                os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
                open(os.path.join(root, rel), "w").close()
            patterns = [f"{root}/*/.env", f"{root}/*/.env.local", f"{root}/*/.env.*.local", f"{root}/*/*/.env", f"{root}/c/*.env", f"{root}/missing/.env"]
            expected = sorted({os.path.realpath(p) for pattern in patterns for p in glob.glob(pattern) if os.path.isfile(p)})
            self.assertEqual(expand_sources(patterns), expected)


class FailureNote(unittest.TestCase):
    M = Masker(key=KEY)

    def event(self, stderr, tool="Bash", **extra):
        return {"hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": {}, "tool_response": {"stdout": "out", "stderr": stderr}, **extra}

    def test_a_reported_failure_is_said_plainly(self):
        out = reply(self.event("boom\n\n[blindfold: exit code 3; reported as success so its output could be masked]\n"), self.M)
        self.assertIn("exited with code 3: it FAILED", out["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("updatedToolOutput", out["hookSpecificOutput"])

    def test_no_note_for_success_a_mention_mid_output_or_grok(self):
        self.assertIsNone(reply(self.event(""), self.M))
        self.assertIsNone(reply(self.event("[blindfold: exit code 3; reported as success so its output could be masked]\nmore"), self.M))
        grok = self.event("[blindfold: exit code 3; reported]\n", hookEventName="PostToolUse")
        self.assertIsNone(reply(grok, self.M))


if __name__ == "__main__":
    unittest.main()


class WorktreeGitWrap(unittest.TestCase):
    """Claude Code's worktree guard refuses git next to a subshell or any `$`."""

    WT = "/r/.claude/worktrees/x"

    def test_git_in_an_isolated_worktree_gets_a_plain_or_report(self):
        from blindfold.bash import wrap

        for command in ("git status --short", "git log | head -3", "cd a && git diff"):
            wrapped = wrap(command, self.WT)
            self.assertTrue(wrapped.startswith(command + " || printf '"), wrapped)
            self.assertNotIn("$", wrapped[len(command):])
            self.assertNotIn("(", wrapped[len(command):])

    def test_what_that_form_cant_hold_is_left_alone_and_the_rest_is_unchanged(self):
        from blindfold.bash import wrap

        for command in ("git commit -m x\ngit push", "git log # note", "exit 3; git x", "git fetch &", "set -e; git pull"):
            self.assertEqual(wrap(command, self.WT), command)
        self.assertEqual(wrap("pwd", self.WT), wrap("pwd"))
        self.assertEqual(wrap("git status", "/r/repo"), wrap("git status"))
        self.assertTrue(wrap("echo digit", self.WT).startswith("(\n"))

    def test_a_failure_is_reported_and_exits_zero_in_both_shells(self):
        import subprocess

        from blindfold.bash import wrap

        for shell in ("zsh", "bash"):
            proc = subprocess.run([shell, "-c", wrap("git --no-such-flag", self.WT)], capture_output=True, text=True, timeout=20)
            self.assertEqual(proc.returncode, 0, shell)
            self.assertIn("[blindfold: exit code nonzero;", proc.stderr, shell)

    def test_the_failure_note_reads_a_nonzero_report(self):
        event = {
            "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {},
            "tool_response": {"stdout": "", "stderr": "x\n[blindfold: exit code nonzero; reported as success so its output could be masked]\n"},
        }
        out = reply(event, Masker(key=KEY))
        self.assertIn("exited with a nonzero code: it FAILED", out["hookSpecificOutput"]["additionalContext"])
