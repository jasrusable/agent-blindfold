"""`blindfold env-set`: one non-secret line into a dotenv file, never showing it."""

import contextlib
import io
import os
import shutil
import stat
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from blindfold import cli, envset, guards, selfguard
from blindfold.config import Config
from blindfold.known import KnownSecret
from blindfold.runtime import build_runtime

from .corpus import j

CFG = Config(use_default_known_secret_files=False)
# Fake secrets, built from fragments.
STRIPE = j("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc")
RANDOM = j("Zq8", "Lm2Xv9", "Rt4Pw7Ks3Nd", "Yb5Hc6Jf1Ga0Ue")


class EnvSet(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="envset-")
        self.env = os.path.join(self.dir, ".env")
        self.rt = build_runtime(CFG, environ={})

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, text, mode=0o640):
        with open(self.env, "w") as handle:
            handle.write(text)
        os.chmod(self.env, mode)

    def read(self):
        with open(self.env) as handle:
            return handle.read()

    def set(self, key, value, path=None, rt=None):
        return envset.set_line(path or self.env, key, value, rt or self.rt)

    def test_adds_a_line_and_keeps_the_rest(self):
        self.write(f"STRIPE_SECRET_KEY={STRIPE}\nDEBUG=1")
        result = self.set("APP_AUDIENCES", "com.example.app,com.example.app.dev")
        self.assertEqual(result, f"APP_AUDIENCES added to {self.env}")
        self.assertEqual(self.read(), f"STRIPE_SECRET_KEY={STRIPE}\nDEBUG=1\nAPP_AUDIENCES=com.example.app,com.example.app.dev\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.env).st_mode), 0o640)

    def test_replaces_a_line_without_reporting_the_old_value(self):
        self.write("A=1\nexport LOG_LEVEL=warning-and-up\nB=2\n")
        result = self.set("LOG_LEVEL", "debug mode")
        self.assertEqual(result, f"LOG_LEVEL replaced in {self.env}")
        self.assertNotIn("warning", result)
        self.assertEqual(self.read(), "A=1\nexport LOG_LEVEL='debug mode'\nB=2\n")
        self.assertEqual(self.set("LOG_LEVEL", "debug mode"), f"LOG_LEVEL unchanged in {self.env}")

    def test_a_value_that_looks_secret_is_refused(self):
        self.write("DEBUG=1\n")
        for key, value in (("PAYMENTS", STRIPE), ("API_SECRET", "hunter2hunter2"), ("SOME_ID", RANDOM)):
            with self.subTest(key=key), self.assertRaises(envset.Refused) as refused:
                self.set(key, value)
            self.assertNotIn(value, str(refused.exception))
        known = build_runtime(CFG, environ={"OTHER_TOKEN": "plainlookingvalue"})
        with self.assertRaises(envset.Refused):
            self.set("HARMLESS", "plainlookingvalue", rt=known)
        self.assertEqual(self.read(), "DEBUG=1\n")

    def test_an_old_value_that_looks_secret_is_never_replaced(self):
        for line in (f"STRIPE_KEY={STRIPE}", "DB_PASSWORD=postgres", f"SOME_ID={RANDOM}", 'SOME_PEM="-----BEGIN'):
            key = line.split("=")[0]
            self.write(line + "\n")
            with self.subTest(line=line), self.assertRaises(envset.Refused) as refused:
                self.set(key, "x")
            self.assertNotIn(line.split("=", 1)[1], str(refused.exception))
            self.assertEqual(self.read(), line + "\n")

    def test_an_old_value_known_only_under_its_own_name_can_be_replaced(self):
        # Every value in a dotenv file is a known secret under its own name.
        self.write("REGION=eu-west-somewhere\n")
        own = replace(self.rt, known=replace(self.rt.known, secrets=[KnownSecret("eu-west-somewhere", "REGION")]))
        self.assertEqual(self.set("REGION", "us-east", rt=own), f"REGION replaced in {self.env}")
        self.write("REGION=eu-west-somewhere\n")
        other = replace(self.rt, known=replace(self.rt.known, secrets=[KnownSecret("eu-west-somewhere", "OTHER_TOKEN")]))
        with self.assertRaises(envset.Refused):
            self.set("REGION", "us-east", rt=other)

    def test_refuses_what_it_cannot_do_safely(self):
        self.write("A=1\nA=2\n")
        cases = [
            ("A", "x", self.env),  # set twice
            ("bad-key", "x", self.env),
            ("B", "two\nlines", self.env),
            ("B", "it's quoted", self.env),
            ("B", "x", os.path.join(self.dir, "config.json")),
        ]
        for key, value, path in cases:
            with self.subTest(key=key, value=value), self.assertRaises(envset.Refused):
                self.set(key, value, path=path)
        self.assertEqual(self.read(), "A=1\nA=2\n")

    def test_a_new_file_is_private(self):
        path = os.path.join(self.dir, ".env.local")
        self.assertEqual(self.set("A", "1", path=path), f"A added to {path} (new file)")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_writes_through_a_symlink(self):
        self.write("A=1\n")
        link = os.path.join(self.dir, "link.env")
        os.symlink(self.env, link)
        self.set("B", "2", path=link)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self.read(), "A=1\nB=2\n")

    def test_refuses_blindfolds_own_files(self):
        target = os.path.join(self.dir, "install", ".env")
        os.makedirs(os.path.dirname(target))
        with mock.patch.object(selfguard, "PROTECTED", [os.path.dirname(target)]):
            with self.assertRaises(envset.Refused):
                self.set("A", "1", path=target)

    def test_the_command_prints_only_the_key(self):
        self.write("export LOG_LEVEL=warning-and-up\n")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("blindfold.envset.load_runtime", return_value=self.rt):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(cli.main(["env-set", self.env, "LOG_LEVEL", "debug"]), 0)
                self.assertEqual(cli.main(["env-set", self.env, "PAYMENTS", STRIPE]), 1)
        self.assertEqual(out.getvalue(), f"LOG_LEVEL replaced in {self.env}\n")
        self.assertNotIn("warning", out.getvalue() + err.getvalue())
        self.assertNotIn(STRIPE, err.getvalue())


class Guards(unittest.TestCase):
    def reason(self, command):
        return guards.command_reason(command, "/tmp", Config(use_default_known_secret_files=False))

    def test_env_set_may_name_a_secret_file(self):
        self.assertIsNone(self.reason("blindfold env-set .envrc FEATURE_X on"))
        self.assertIsNone(self.reason("~/.local/share/agent-blindfold/bin/blindfold env-set ~/.netrc A b"))

    def test_everything_else_still_may_not(self):
        for command in (
            "cat .envrc",
            "blindfold scan .envrc",
            "blindfold env-set .env A b; cat .envrc",
        ):
            with self.subTest(command=command):
                self.assertIsNotNone(self.reason(command))

    def test_the_refusal_points_at_env_set(self):
        self.assertIn("env-set FILE KEY VALUE", self.reason("cat .envrc"))

    def test_selfguard_lets_the_installed_launcher_set_a_line(self):
        install = os.path.join(tempfile.mkdtemp(prefix="envset-guard-"), "install")
        try:
            os.makedirs(install)
            command = f"{install}/bin/blindfold env-set /tmp/app/.env A b"
            self.assertIsNone(selfguard.reason({"command": command}, False, None, protected=[install], settings=[]))
            self.assertIsNotNone(
                selfguard.reason({"command": f"{install}/bin/blindfold env-set /tmp/.env A b > {install}/x"}, False, None, protected=[install], settings=[])
            )
        finally:
            shutil.rmtree(os.path.dirname(install), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
