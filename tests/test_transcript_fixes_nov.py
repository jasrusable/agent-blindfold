"""Fixes for what a review of two weeks of real sessions (Nov 9-23, 2026) found:
false positives in masking and in the guards. Each is a case from the wild."""

import base64
import json
import os
import shutil
import string
import tempfile
import unittest

from blindfold import selfguard
from blindfold.known import parse_env_text
from blindfold.mask import Masker
from blindfold.structure import mask_value

from . import corpus
from .test_fail_closed import OP, denied, pre

M = Masker(key=b"n" * 32)


def masked(text):
    return M.mask(text)[1]


class FileNames(unittest.TestCase):
    def test_a_token_before_a_file_extension_is_a_file_name(self):
        # In the wild: `git ls-files` output, camelCase stems masked as high-entropy.
        stem = corpus.rand(40)
        for name in (f"src/hooks/{stem}.ts", f"{stem}.test.tsx", f"web/{stem}.png", f"{stem}.json"):
            self.assertEqual(masked(name), [], name)

    def test_the_same_token_elsewhere_is_still_masked(self):
        token = corpus.rand(40)
        for text in (f"key {token} end", f"{token}.tsxx", f"{token}.example.com"):
            self.assertTrue(masked(text), text)


class Images(unittest.TestCase):
    def test_random_looking_pixel_bytes_are_not_a_secret(self):
        # In the wild: website PNGs masked whole as binary-with-secret, for compressed pixel data.
        noise = corpus.rand(4000, string.ascii_letters + string.digits + "+/").encode()
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(16) + noise + bytes(16)).decode()
        for block in ({"type": "image", "file": {"base64": png}}, {"type": "image", "source": {"type": "base64", "data": png}}):
            self.assertEqual(mask_value(M, block), (block, []))

    def test_a_vendor_key_in_an_image_still_masks_it(self):
        text = f"tEXtComment STRIPE_API_KEY={corpus.STRIPE_LIVE}".encode()
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(16) + text).decode()
        out, findings = mask_value(M, {"type": "image", "file": {"base64": png}})
        self.assertTrue(findings)
        self.assertNotIn(png, json.dumps(out))


class DevValues(unittest.TestCase):
    def test_short_lowercase_labels_are_not_known_secrets(self):
        # In the wild: dev .env stand-ins of 8 and 11 characters refused unrelated commands.
        lower = string.ascii_lowercase
        for value in (corpus.j(corpus.rand(2, lower), "_", corpus.rand(5, lower)), corpus.j(corpus.rand(4, lower), "-", corpus.rand(6, lower))):
            self.assertEqual(parse_env_text(f"RESEND_WEBHOOK_SECRET={value}", 8), [], value)

    def test_random_values_still_are(self):
        value = corpus.j("whsec", "_", corpus.rand(32))
        self.assertEqual([s.name for s in parse_env_text(f"RESEND_WEBHOOK_SECRET={value}", 8)], ["RESEND_WEBHOOK_SECRET"])


class PublicValues(unittest.TestCase):
    def test_vite_variables_are_bundled_so_public(self):
        # In the wild: VITE_DEV_ALLOWED_HOSTS, a tailnet host name, masked everywhere.
        host = corpus.j(corpus.rand(8, string.ascii_lowercase), "-pc.tail", corpus.rand(6, "0123456789abcdef"), ".ts.net")
        self.assertEqual(parse_env_text(f"VITE_DEV_ALLOWED_HOSTS={host}", 8), [])

    def test_a_vite_name_that_says_secret_is_still_secret(self):
        value = corpus.rand(40)
        for name in ("VITE_API_PROXY_TOKEN", "VITE_ADMIN_PASSWORD"):
            self.assertEqual([s.name for s in parse_env_text(f"{name}={value}", 8)], [name])

    def test_stand_ins_in_docs_and_fixtures(self):
        for text in ("| `--token <token>` | Uses this token |", "'https://user:pass@example.com/x'"):
            self.assertEqual(masked(text), [], text)


class CommandText(unittest.TestCase):
    def test_names_only_environment_listings_pass(self):
        for command in ("env | cut -d= -f1", "env | cut -d'=' -f1 | grep -i gh", "env | cut -f1 -d=", "env | sed 's/=.*//'"):
            self.assertFalse(denied(pre(command)), command)

    def test_value_listings_are_still_refused(self):
        for command in ("env", "env | cut -d= -f2", "env | cut -d= -f1-2", "env | sort", "env | cut -d= -f1,2",
                        "env | cut -d= -f1 --complement", "env | cut -f1 -d= --complement", "env | cut -d= -f1 -s --complement"):
            self.assertTrue(denied(pre(command)), command)

    def test_searching_for_command_text_is_not_running_it(self):
        # In the wild: grep patterns over docs that mention 1Password commands.
        for command in (f"grep -n -iE 'vault|{OP}://|{OP} read|item' agent-secrets.md", f'grep -rn "{OP} item get|{OP} read" bin/'):
            self.assertFalse(denied(pre(command)), command)

    def test_code_fed_to_an_interpreter_is_not_shell(self):
        # In the wild: a Python heredoc editing docs that mention env and 1Password commands.
        command = f"python3 - <<'EOF'\ns = open('a.md').read().replace('x', '| `{OP} read` |\\nenv\\n')\nEOF"
        self.assertFalse(denied(pre(command)))

    def test_real_uses_are_still_refused(self):
        for command in (f"{OP} read {OP}://v/i/f", f"bash <<'EOF'\n{OP} read {OP}://v/i/f\nEOF", "bash <<'EOF'\nenv\nEOF",
                        f"python3 - <<EOF\n$({OP} read {OP}://v/i/f)\nEOF", f"grep x $({OP} read {OP}://v/i/f)",
                        f'grep x "$({OP} read {OP}://v/i/f)"', f'grep x "`{OP} read {OP}://v/i/f`"',
                        f"grep 'x' $({OP} read {OP}://v/i/f)", f"grep \"x'\" '$({OP} read {OP}://v/i/f)'",
                        f"python3 -c 'import sys' <<'EOF'\n{OP} read {OP}://v/i/f\nEOF"):
            self.assertTrue(denied(pre(command)), command)


class SshReads(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sshguard-")
        self.install = os.path.join(self.root, "install")
        os.makedirs(self.install)
        self.settings = os.path.join(self.root, "settings.json")
        with open(self.settings, "w") as handle:
            json.dump({"hooks": {}}, handle)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def reason(self, command):
        return selfguard.reason({"command": command}, False, None, protected=[self.install], settings=[self.settings])

    def test_reading_over_ssh_is_a_read(self):
        # In the wild: `ssh host 'grep -n env ~/.claude/settings.json'` refused as a change to blindfold.
        for command in (f"ssh -o ConnectTimeout=5 host 'grep -n env {self.settings}'", f"ssh host cat {self.install}/README.md",
                        f"ssh -p 22 host 'sed -n 1,9p {self.settings} | head'"):
            self.assertIsNone(self.reason(command), command)

    def test_writing_over_ssh_or_feeding_it_a_script_is_refused(self):
        for command in (f"ssh host 'sed -i s/a/b/ {self.settings}'", f"ssh host 'echo x > {self.install}/x'",
                        f"ssh host bash -s <<'EOF'\nrm {self.settings}\nEOF", f"echo rm {self.settings} | ssh host sh",
                        f"ssh host python3 -c 'open(\"{self.settings}\", \"w\")'", f"ssh host rm {self.settings}",
                        # Options that write or run here: a log file, a proxy or local command, a config, a socket.
                        f"ssh -E {self.settings} host true", f"ssh -E{self.settings} host cat x",
                        f"ssh -o ProxyCommand='rm {self.settings}' host true", f"ssh -oLocalCommand='rm {self.settings}' -o PermitLocalCommand=yes host ls",
                        f"ssh -F {self.install}/cfg host ls", f"ssh -S {self.install}/sock host ls", f"ssh -L {self.install}/s:h:2 host ls"):
            self.assertTrue(self.reason(command), command)


class ReviewCases(unittest.TestCase):
    """What a fresh review of these fixes found they let through."""

    def test_vite_key_names_stay_secret(self):
        value = corpus.rand(24)
        for name in ("VITE_OPENAI_KEY", "VITE_STRIPE_KEY", "VITE_SUPABASE_KEY"):
            self.assertEqual([s.name for s in parse_env_text(f"{name}={value}", 8)], [name])

    def test_word_passwords_and_tokens_stay_secret(self):
        for line in ("DB_PASSWORD=" + corpus.j("red", "-fox-", "42"), "POSTGRES_PASSWORD=" + corpus.j("hunter", "_22"),
                     "API_TOKEN=" + corpus.j("k3j9", "-x82mq1")):
            self.assertTrue(parse_env_text(line, 8), line)

    def test_random_keys_in_image_and_pdf_text_are_masked(self):
        key = corpus.rand(40)
        chunk = b"Comment\x00" + key.encode()
        png = b"\x89PNG\r\n\x1a\n" + len(chunk).to_bytes(4, "big") + b"tEXt" + chunk + bytes(4)
        pdf = b"%PDF-1.4\nBT (" + key.encode() + b") Tj ET\n"
        for raw in (png, pdf):
            out, findings = mask_value(M, {"type": "image", "file": {"base64": base64.b64encode(raw).decode()}})
            self.assertTrue(findings, raw[:8])

    def test_a_secret_named_value_before_an_extension_is_masked(self):
        token = corpus.rand(40)
        self.assertTrue(masked(f"TOKEN={token}.json"))

    def test_code_options_and_rg_pre_keep_the_checks(self):
        for command in (f"python3 -E - <<'EOF'\n{OP} read {OP}://v/i/f\nEOF", f"perl -n <<'EOF'\n{OP} read {OP}://v/i/f\nEOF",
                        f"rg --pre 'sh -c \"{OP} read {OP}://v/i/f\"' x"):
            self.assertTrue(denied(pre(command)), command)


class SshDepth(SshReads):
    def test_deep_nesting_is_refused_fast(self):
        import time
        start = time.monotonic()
        self.assertTrue(self.reason("ssh h " * 800 + f"rm {self.settings}"))
        self.assertLess(time.monotonic() - start, 1.0)


if __name__ == "__main__":
    unittest.main()
