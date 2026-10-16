"""Fixes from the 2026-10-16 adversarial review, each pinned by a test."""

import json
import os
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from blindfold import bash, hook
from blindfold.config import load_config
from blindfold.known import KnownSecret, parse_env_text
from blindfold.mask import Masker
from blindfold.structure import deep_map, withhold

from . import corpus
from .helpers import reply, runtime

M = Masker(known=[KnownSecret(corpus.rand(30), "API_SECRET")], key=b"r" * 32)


class BashWrapper(unittest.TestCase):
    """Run the wrapper under the real shells: every way a command or shell can
    fail must exit 0 with the code reported, and behaviour must not change."""

    CASES = [
        ("echo out; false", 1),
        ("echo out; exit 3", 3),
        ("set -e; false; echo never", 1),
        ("set -euo pipefail; echo $NOPE_UNSET_VAR; echo never", None),
        ("set -u; echo $NOPE_UNSET_VAR; echo never", None),
        ("setopt nounset 2>/dev/null; set -o nounset; echo $NOPE_UNSET_VAR; echo never", None),
        ("echo ${NOPE_UNSET_VAR:?unset}; echo never", None),
        ("source /dev/stdin <<< 'exit 6'", 6),
        ("echo ok", 0),
        ("# just a comment", 0),
    ]

    def run_wrapped(self, command, shell):
        return subprocess.run([shell, "-c", bash.wrap(command)], capture_output=True, text=True, timeout=20)

    def test_every_failure_exits_zero_and_reports(self):
        for shell in ("/bin/zsh", "/bin/bash"):
            for command, code in self.CASES:
                with self.subTest(shell=shell, command=command):
                    proc = self.run_wrapped(command, shell)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertNotIn("never", proc.stdout, "set -e / nounset must still stop the script")
                    if code == 0:
                        self.assertNotIn(bash.MARKER, proc.stderr)
                    elif code is None:
                        self.assertIn(bash.MARKER, proc.stderr)
                    else:
                        self.assertIn(f"{bash.MARKER} {code};", proc.stderr)

    def test_group_keeps_shell_state_and_heredocs_work(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = self.run_wrapped(f"cd {directory}\npwd\ncat <<EOF\nhello\nEOF", "/bin/zsh")
            self.assertEqual(os.path.realpath(proc.stdout.splitlines()[0]), os.path.realpath(directory))
            self.assertIn("hello", proc.stdout)

    def test_plain_commands_stay_in_the_same_shell(self):
        for command in ("npm test", "cd sub && ls", "git status"):
            self.assertEqual(bash.wrap(command).split("\n")[1], "{", command)

    def test_idempotent_and_skips_only_comment_only_commands(self):
        once = bash.wrap("ls")
        self.assertEqual(bash.wrap(once), once)
        self.assertEqual(bash.wrap("   "), "   ")
        self.assertEqual(bash.wrap("# note\n\n"), "# note\n\n")

    def test_commands_that_could_dodge_the_trap_are_still_reported(self):
        for shell in ("/bin/zsh", "/bin/bash"):
            for command, code in (
                ("echo a; false \\", 1),
                (f"echo '{bash.MARKER}'; exit 2", 2),
                ("exec false", 1),
                ("trap - EXIT; exit 3", 3),
                ("trap '' EXIT; echo x; exit 4", 4),
            ):
                with self.subTest(shell=shell, command=command):
                    proc = self.run_wrapped(command, shell)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertIn(f"{bash.MARKER} {code};", proc.stderr)


class Prompts(unittest.TestCase):
    def test_a_pasted_vendor_secret_is_blocked(self):
        out = reply({"hook_event_name": "UserPromptSubmit", "prompt": f"use {corpus.GITHUB_PAT} to push"}, M)
        self.assertEqual(out["decision"], "block")
        self.assertIn("github-token", out["reason"])
        self.assertNotIn(corpus.GITHUB_PAT, out["reason"])

    def test_name_based_judgements_do_not_block_a_prompt(self):
        self.assertIsNone(reply({"hook_event_name": "UserPromptSubmit", "prompt": "set password: Summer2024 in the yaml"}, M))


class Structure(unittest.TestCase):
    def test_only_string_payloads_are_skipped(self):
        value = {"image": {"note": f"STRIPE_API_KEY={corpus.STRIPE_LIVE}"}, "base64": "QUJD"}
        masked = deep_map(value, lambda s: M.mask(s)[0])
        self.assertNotIn(corpus.STRIPE_LIVE, json.dumps(masked))
        self.assertEqual(masked["base64"], "QUJD")

    def test_mcp_media_data_is_left_intact(self):
        block = [{"type": "image", "data": corpus.png_base64(500), "mimeType": "image/png"}]
        self.assertEqual(deep_map(block, lambda s: M.mask(s)[0]), block)

    def test_withheld_output_replaces_keys_that_are_not_schema_names(self):
        value = {"stdout": "x", corpus.STRIPE_LIVE: {"a": 1}}
        out = withhold(value, "W")
        self.assertIn("stdout", out)
        self.assertNotIn(corpus.STRIPE_LIVE, json.dumps(out))


class TimeBudget(unittest.TestCase):
    def test_an_over_budget_call_is_withheld(self):
        def slow(*_args):
            time.sleep(5)

        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": "secret-ish", "stderr": ""}}
        with mock.patch.object(hook, "BUDGET_SECONDS", 1), mock.patch("blindfold.hook.handle", side_effect=slow):
            started = time.monotonic()
            out = hook.respond(event, runtime(M))
        self.assertLess(time.monotonic() - started, 3)
        self.assertIn("withheld", json.dumps(out))


class ConfigTypes(unittest.TestCase):
    def load(self, raw):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "config.json")
            with open(path, "w") as handle:
                json.dump(raw, handle)
            with mock.patch("blindfold.config.CONFIG_PATH", path):
                return load_config()

    def test_wrong_types_are_rejected(self):
        for raw in ({"entropy": "false"}, {"extra_known_secret_files": "~/.env"}, {"allow_ids": [1]}, {"min_known_length": True}, {"nope": 1}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.load(raw)

    def test_extra_files_add_to_the_defaults(self):
        config = self.load({"extra_known_secret_files": ["~/work/*/.env"]})
        self.assertIn("~/work/*/.env", config.known_secret_files)
        self.assertGreater(len(config.known_secret_files), 1)


class EnvironmentValues(unittest.TestCase):
    def test_shell_state_and_paths_are_never_known_secrets(self):
        from blindfold.known import load_known_secrets

        token = corpus.rand(30)
        loaded = load_known_secrets([], environ={"PWD": "/Users/me/project", "OLDPWD": "/tmp/x", "HOME": "/Users/me",
                                                 "DB_PWD": "/etc/odd/path", "GITHUB_TOKEN": token})
        self.assertEqual([s.name for s in loaded.secrets], ["GITHUB_TOKEN"])


class KnownParsing(unittest.TestCase):
    def test_quoted_value_with_a_comment(self):
        value = "Q" + corpus.rand(19)
        self.assertEqual([s.value for s in parse_env_text(f"API_TOKEN='{value}' # rotated monthly", 8)], [value])

    def test_weak_dev_values_are_not_known_secrets(self):
        text = "DB_PASSWORD=postgres\nSECRET_KEY=development\nREAL_TOKEN=" + corpus.rand(24)
        self.assertEqual(sorted(s.name for s in parse_env_text(text, 8)), ["REAL_TOKEN"])

    def test_short_name_forms_load_as_known(self):
        self.assertEqual([s.name for s in parse_env_text("SMTP_PASS=Abc123def456", 8)], ["SMTP_PASS"])


class RoundTwo(unittest.TestCase):
    """Fixes from the second review round."""

    def test_weak_known_values_match_whole_words_and_never_refuse(self):
        long_weak = "correcthorsebatterystaple"
        m = Masker(known=[KnownSecret(long_weak, "DB_PASSWORD", weak=True)], key=b"w" * 32)
        self.assertNotIn(long_weak, m.mask(f"pw {long_weak} end")[0])
        self.assertEqual(m.mask(f"x{long_weak}y")[1], [], "only whole words")
        out = reply({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"psql -p {long_weak}"},
                     "hookEventName": "pre_tool_use"}, m)
        self.assertIsNone(out, "a word-like value never refuses a call")

    def test_random_short_passwords_stay_known(self):
        self.assertEqual([s.name for s in parse_env_text("DB_PASSWORD=Xk9#mP2k", 8)], ["DB_PASSWORD"])

    def test_paths_and_labels_under_key_names_are_not_known(self):
        text = "SSL_KEY=./certs/key.pem\nKMS_KEY=alias/app\nS3_BUCKET_KEY=uploads/images\nCACHE_KEY=user_profile_v2\nMAILGUN_KEY=key-" + corpus.hexs(32)
        self.assertEqual([s.name for s in parse_env_text(text, 8)], ["MAILGUN_KEY"])

    def test_a_weak_password_inside_a_url_is_not_known(self):
        loaded = [s.value for s in parse_env_text("DATABASE_URL=postgres://postgres:password@localhost:5432/app", 8)]
        self.assertNotIn("password", loaded)

    def test_redis_password_without_user_is_known(self):
        self.assertIn("S3cretRedisPw", [s.value for s in parse_env_text("REDIS_URL=redis://:S3cretRedisPw@cache:6379", 8)])

    def test_content_hashes_with_a_prefix_are_not_keys(self):
        for text in (f"integrity sha256-{corpus.hexs(64)}", f"sha512-{corpus.hexs(64)}"):
            self.assertEqual(M.mask(text)[1], [], text[:20])

    def test_ssm_with_type_between_reverse_order_and_netrc_default(self):
        for text, secret in (
            ('{"Name": "/prod/db/password", "Type": "SecureString", "Value": "Abc123def456"}', "Abc123def456"),
            ('{"Value": "Abc123def456", "Name": "API_TOKEN"}', "Abc123def456"),
            ("default login anonymous password Abc123def456x", "Abc123def456x"),
            ("CONN=Server=x;Password=MyP4ss!;", "MyP4ss!"),
        ):
            with self.subTest(text=text[:30]):
                self.assertNotIn(secret, M.mask(text)[0])

    def test_local_database_url_in_a_prompt_is_not_blocked_and_ids_are_offered(self):
        self.assertIsNone(reply({"hook_event_name": "UserPromptSubmit", "prompt": "connect to postgresql://user:pass1234@localhost/db"}, M))
        out = reply({"hook_event_name": "UserPromptSubmit", "prompt": f"use {corpus.GITHUB_PAT}"}, M)
        self.assertRegex(out["reason"], r"id [0-9a-f]{6}")

    def test_base64_text_under_a_skip_key_is_masked_but_images_are_not(self):
        import base64 as b64

        encoded_env = b64.b64encode(f"STRIPE_API_KEY={corpus.STRIPE_LIVE}\nOTHER=1\n".encode()).decode()
        masked = deep_map({"base64": encoded_env}, lambda s: M.mask(s)[0])
        self.assertNotEqual(masked["base64"], encoded_env)
        png = b64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4).decode()
        self.assertEqual(deep_map({"base64": png}, lambda s: M.mask(s)[0])["base64"], png)

    def test_skip_keys_only_skip_real_blobs(self):
        url = "https://bucket.s3.amazonaws.com/x?X-Amz-Signature=" + corpus.hexs(64)
        masked = deep_map({"image": url, "base64": corpus.rand(200, corpus.ALNUM + "+/")}, lambda s: M.mask(s)[0])
        self.assertNotIn(corpus.hexs(1) * 0 + url.split("=")[-1], masked["image"])
        doc = [{"type": "document", "data": f"API_SECRET leaked: STRIPE_API_KEY={corpus.STRIPE_LIVE}"}]
        self.assertNotIn(corpus.STRIPE_LIVE, json.dumps(deep_map(doc, lambda s: M.mask(s)[0])))

    def test_a_huge_known_value_cannot_break_masking(self):
        huge = "%" * 7000 + corpus.rand(20)
        m = Masker(known=[KnownSecret(huge, "BIG_SECRET")], key=b"h" * 32)
        self.assertEqual(m.mask("ordinary text")[1], [])


# Assembled at runtime so no file spells out a full secret-dump command.
KEYCHAIN = "secu" + "rity"
OP = "o" + "p"


class BlockedCommands(unittest.TestCase):
    def deny(self, command):
        out = reply({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}, M)
        return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_bare_secret_dumps_are_refused_in_every_command_position(self):
        read = f"{OP} read op://Vault/item/password"
        for command in (
            f"{KEYCHAIN} find-" "generic-password -s svc -w", f"{KEYCHAIN} find-" "internet-password -gs host",
            f"{KEYCHAIN} dump-" "keychain", read, f"{OP} item get Stripe --reveal", f"{OP} item get Stripe --format json",
            f"{OP} inject -i tpl.env", f"{OP} document get cert", f"{OP} --account work read op://V/i/f",
            f"/usr/bin/{KEYCHAIN} find-" "generic-password -w -s svc",
            f"echo x && {read}", f"echo x; {read}", f"echo x\n{read}", f"TOKEN=$({read})", f"TOKEN=`{read}`",
            f"{{ {read}; }}", f"if true; then {read}; fi", f"for i in 1; do {read}; done",
            f"sudo {read}", f"env A=1 {read}", f"command {read}", f"nohup {read}", f"time {read}",
            f"A=1 B=2 {read}", f"xargs {OP} read < refs",
        ):
            with self.subTest(command=command):
                self.assertTrue(self.deny(command))

    def test_text_that_only_mentions_them_is_fine(self):
        for command in (f"git commit -m 'stop using {OP} read in scripts'", f"grep -r '{OP} read' docs/",
                        f"{OP} run --env-file=.env -- npm start", f"{KEYCHAIN} find-" "generic-password -s svc", f"{OP} item list"):
            with self.subTest(command=command):
                self.assertFalse(self.deny(command))

    def test_an_invalid_user_regex_takes_the_safe_fallback(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "config.json")
            with open(path, "w") as handle:
                json.dump({"blocked_commands": ["(unclosed"]}, handle)
            with mock.patch("blindfold.config.CONFIG_PATH", path), self.assertRaises(ValueError):
                load_config()


class StrictSubshellAndBlobs(unittest.TestCase):
    def test_eval_source_and_exec_run_in_a_subshell(self):
        for command in ("eval 'false'", "source ./x.sh", ". ./x.sh", "command exec ls", "docker exec app ls"):
            self.assertEqual(bash.wrap(command).split("\n")[1], "(", command)

    def test_a_blob_that_starts_binary_but_is_not_an_image_is_masked(self):
        import base64 as b64

        crafted = b64.b64encode(bytes(range(200)) + f"STRIPE_API_KEY={corpus.STRIPE_LIVE}".encode()).decode()
        self.assertNotEqual(deep_map({"base64": crafted}, lambda s: M.mask(s)[0])["base64"], crafted)


if __name__ == "__main__":
    unittest.main()
