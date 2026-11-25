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
from blindfold.cli_paths import LAUNCHER
from blindfold.config import Config
from blindfold.known import KnownSecret
from blindfold.runtime import build_runtime

from .corpus import j

CFG = Config(use_default_known_secret_files=False)
# Fake secrets, built from fragments.
STRIPE = j("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc")
RANDOM = j("Zq8", "Lm2Xv9", "Rt4Pw7Ks3Nd", "Yb5Hc6Jf1Ga0Ue")
DOT_ENV = "." + "env"


class EnvSet(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="envset-")
        self.env = os.path.join(self.dir, DOT_ENV)
        self.rt = build_runtime(CFG, environ={})

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, text, mode=0o640, path=None):
        with open(path or self.env, "w", newline="") as handle:
            handle.write(text)
        os.chmod(path or self.env, mode)

    def read(self, path=None):
        with open(path or self.env, newline="") as handle:
            return handle.read()

    def set(self, key, value, path=None, rt=None, environ=None):
        return envset.set_line(path or self.env, key, value, rt or self.rt, environ={} if environ is None else environ)

    def refused(self, key, value, **kwargs):
        with self.assertRaises(envset.Refused) as refused:
            self.set(key, value, **kwargs)
        return str(refused.exception)

    def test_adds_a_line_and_keeps_the_rest(self):
        self.write(f"STRIPE_SECRET_KEY={STRIPE}\nDEBUG=1")
        result = self.set("APP_AUDIENCES", "com.example.app,com.example.app.dev")
        self.assertEqual(result, f"APP_AUDIENCES added to {self.env}")
        self.assertEqual(self.read(), f"STRIPE_SECRET_KEY={STRIPE}\nDEBUG=1\nAPP_AUDIENCES=com.example.app,com.example.app.dev\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.env).st_mode), 0o640)
        self.assertFalse(os.path.exists(self.env + envset.BACKUP_SUFFIX))

    def test_replaces_a_line_keeping_a_private_backup(self):
        before = "A=1\r\nexport LOG_LEVEL=warning-and-up\r\nB=2\r\n"
        self.write(before)
        result = self.set("LOG_LEVEL", "debug mode")
        self.assertTrue(result.startswith(f"LOG_LEVEL replaced in {self.env}"))
        self.assertNotIn("warning", result)
        self.assertEqual(self.read(), "A=1\r\nexport LOG_LEVEL='debug mode'\r\nB=2\r\n")
        backup = self.env + envset.BACKUP_SUFFIX
        self.assertEqual(self.read(backup), before)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        self.assertEqual(self.set("LOG_LEVEL", "debug mode"), f"LOG_LEVEL unchanged in {self.env}")

    def test_a_value_that_looks_secret_is_refused(self):
        self.write("DEBUG=1\n")
        for key, value in (("PAYMENTS", STRIPE), ("API_SECRET", "hunter2hunter2"), ("SOME_ID", RANDOM)):
            with self.subTest(key=key):
                self.assertNotIn(value, self.refused(key, value))
        known = build_runtime(CFG, environ={"OTHER_TOKEN": "plainlookingvalue"})
        self.refused("HARMLESS", "plainlookingvalue", rt=known)
        self.assertEqual(self.read(), "DEBUG=1\n")

    def test_an_old_value_that_looks_secret_is_never_replaced(self):
        for line in (f"STRIPE_KEY={STRIPE}", "DB_PASSWORD=postgres", f"SOME_ID={RANDOM}", "WEBHOOK_SECRET=abc"):
            key = line.split("=")[0]
            self.write(line + "\n")
            with self.subTest(line=line):
                self.assertNotIn(line.split("=", 1)[1], self.refused(key, "x"))
            self.assertEqual(self.read(), line + "\n")

    def test_an_old_value_known_only_under_its_own_name_can_be_replaced(self):
        # Every value in a dotenv file is a known secret under its own name.
        self.write("REGION=eu-west-somewhere\n")
        own = replace(self.rt, known=replace(self.rt.known, secrets=[KnownSecret("eu-west-somewhere", "REGION")]))
        self.assertTrue(self.set("REGION", "us-east", rt=own).startswith("REGION replaced"))
        self.write("REGION=eu-west-somewhere\n")
        other = replace(self.rt, known=replace(self.rt.known, secrets=[KnownSecret("eu-west-somewhere", "OTHER_TOKEN")]))
        self.refused("REGION", "us-east", rt=other)

    def test_lines_inside_a_value_over_several_lines_are_not_keys(self):
        before = 'CERT="line1\nFOO=abc\nline3"\nBAR=1\n'
        self.write(before)
        self.assertEqual(self.set("FOO", "x"), f"FOO added to {self.env}")
        self.assertEqual(self.read(), before + "FOO=x\n")
        self.write('CERT="never closed\nFOO=1\n')
        self.refused("FOO", "x")
        # Only \n ends a line: U+2028 is part of X's value.
        self.write("X=1\u2028FOO=2\n")
        self.assertEqual(self.set("FOO", "x"), f"FOO added to {self.env}")
        self.assertEqual(self.read(), "X=1\u2028FOO=2\nFOO=x\n")

    def test_refuses_what_it_cannot_do_safely(self):
        self.write("A=1\nA=2\nC: 3\n")
        cases = [
            ("A", "x", self.env),  # set twice
            ("C", "x", self.env),  # a form it can't replace
            ("bad-key", "x", self.env),
            ("B", "two\nlines", self.env),
            ("B", "sep\u2028arated", self.env),
            ("B", "tab\tbed", self.env),
            ("B", "it's quoted", self.env),
            ("PATH", "/tmp/x:/usr/bin", self.env),
            ("LD_PRELOAD", "/tmp/x.so", self.env),
            ("BLINDFOLD_CONFIG", "/tmp/x.json", self.env),
            ("B", "x", os.path.join(self.dir, "config.json")),
            ("B", "x", os.path.join(self.dir, ".envrc")),
        ]
        for key, value, path in cases:
            with self.subTest(key=key, value=value):
                self.refused(key, value, path=path)
        self.refused("B", "x", environ={"BLINDFOLD_CONFIG": "/tmp/c.json"})
        self.refused("B", "x", environ={"BLINDFOLD_HOME": "/tmp/h"})
        self.assertEqual(self.read(), "A=1\nA=2\nC: 3\n")

    def test_a_byte_order_mark_does_not_hide_a_key(self):
        self.write("\ufeffA=1\n")
        self.assertTrue(self.set("A", "2").startswith("A replaced"))
        self.assertEqual(self.read(), "\ufeffA=2\n")

    def test_a_new_file_is_private(self):
        path = os.path.join(self.dir, DOT_ENV + ".local")
        self.assertEqual(self.set("A", "1", path=path), f"A added to {path} (new file)")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(sorted(os.listdir(self.dir)), [DOT_ENV + ".local"])

    def test_writes_through_a_symlink(self):
        self.write("A=1\n")
        link = os.path.join(self.dir, "link.env")
        os.symlink(self.env, link)
        self.set("B", "2", path=link)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self.read(), "A=1\nB=2\n")

    def test_refuses_blindfolds_own_files(self):
        target = os.path.join(self.dir, "install", DOT_ENV)
        os.makedirs(os.path.dirname(target))
        with mock.patch.object(selfguard, "PROTECTED", [os.path.dirname(target)]):
            self.refused("A", "1", path=target)
        hook = os.path.join(self.dir, "installed", "bin", "blindfold")
        target = os.path.join(self.dir, "installed", DOT_ENV)
        with mock.patch.object(cli, "installed_hooks", return_value={"claude": hook}):
            self.refused("A", "1", path=target)

    def test_the_command_prints_only_the_key(self):
        self.write("export LOG_LEVEL=warning-and-up\n")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("blindfold.envset.load_runtime", return_value=self.rt), mock.patch.dict(os.environ, clear=False) as env:
            env.pop("BLINDFOLD_CONFIG", None)
            env.pop("BLINDFOLD_HOME", None)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(cli.main(["env-set", self.env, "LOG_LEVEL", "debug"]), 0)
                self.assertEqual(cli.main(["env-set", self.env, "PAYMENTS", STRIPE]), 1)
                with open(self.env, "wb") as handle:
                    handle.write(b"A=caf\xe9\n")
                self.assertEqual(cli.main(["env-set", self.env, "B", "1"]), 1)
        self.assertTrue(out.getvalue().startswith(f"LOG_LEVEL replaced in {self.env}"))
        self.assertNotIn("warning", out.getvalue() + err.getvalue())
        self.assertNotIn(STRIPE, err.getvalue())
        self.assertNotIn("0xe9", err.getvalue())


class Guards(unittest.TestCase):
    def reason(self, command):
        return guards.command_reason(command, "/tmp", Config(use_default_known_secret_files=False))

    def test_env_set_may_name_a_secret_file(self):
        self.assertIsNone(self.reason(f"{LAUNCHER} env-set .envrc FEATURE_X on"))
        self.assertIsNone(self.reason(f"{LAUNCHER} env-set ~/.netrc A b"))

    def test_everything_else_still_may_not(self):
        for command in (
            "cat .envrc",
            "blindfold scan .envrc",
            f"{LAUNCHER} env-set .env A b; cat .envrc",
            f"{LAUNCHER} env-set /tmp/a.env K V > .envrc",
            f"{LAUNCHER} env-set /tmp/a.env K V >> .envrc",
            f"{LAUNCHER} env-set /tmp/a.env K V 2>.envrc",
            f"{LAUNCHER} env-set /tmp/a.env K V &> .envrc",
            f"{LAUNCHER} env-set .envrc K =(cat .envrc)",
            f"{LAUNCHER} env-set .envrc K $X",
            "/tmp/x/blindfold env-set .envrc K V",
            f"blindfold() {{ cat \"$2\"; }}; {LAUNCHER} env-set .envrc K V",
            f"alias blindfold=cat; {LAUNCHER} env-set .envrc K V",
            "cat .env.blindfold-bak",
            "cat .env.blindfold-tmpab12",
        ):
            with self.subTest(command=command):
                self.assertIsNotNone(self.reason(command))

    def test_the_refusal_points_at_env_set(self):
        self.assertIn("env-set FILE KEY VALUE", self.reason("cat .envrc"))

    def test_selfguard_lets_only_the_real_launcher_set_a_line(self):
        install = os.path.join(tempfile.mkdtemp(prefix="envset-guard-"), "install")
        try:
            os.makedirs(install)

            def reason(command):
                return selfguard.reason({"command": command}, False, None, protected=[install], settings=[])

            self.assertIsNone(reason(f"{LAUNCHER} env-set /tmp/app/.env A b"))
            self.assertIsNotNone(reason(f"{LAUNCHER} env-set /tmp/.env A b > {install}/x"))
            self.assertIsNotNone(reason(f"/tmp/x/blindfold env-set {install}/.env A b"))
        finally:
            shutil.rmtree(os.path.dirname(install), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
