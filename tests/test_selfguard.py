"""blindfold refuses tool calls that would change blindfold itself."""

import json
import os
import shutil
import tempfile
import unittest

from blindfold import selfguard
from blindfold.mask import Masker

from .helpers import reply


class SelfGuard(unittest.TestCase):
    def setUp(self):
        # Under ~ so the ~/… and $HOME/… spellings are exercised for real.
        cache = os.path.expanduser("~/.cache/blindfold")
        os.makedirs(cache, exist_ok=True)
        self.root = tempfile.mkdtemp(prefix="guardtest-", dir=cache)
        self.install = os.path.join(self.root, "install")
        self.config = os.path.join(self.root, "config")
        self.link = os.path.join(self.root, "skill-link")
        self.settings = os.path.join(self.root, "settings.json")
        for path in (self.install, self.config):
            os.makedirs(path)
        os.symlink(self.install, self.link)
        hook = {"hooks": [{"type": "command", "command": f"{self.install}/bin/blindfold hook"}]}
        with open(self.settings, "w") as handle:
            json.dump({"permissions": {"allow": []}, "hooks": {"PostToolUse": [{"matcher": ".*", **hook}]}}, handle, indent=2)
        self.home_form = "~" + self.install[len(os.path.expanduser("~")):]

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def reason(self, tool_input, read_only=False, cwd=None):
        protected = [self.install, self.config, self.link]
        return selfguard.reason(tool_input, read_only, cwd, protected=protected, settings=[self.settings])

    def test_writes_inside_protected_paths_are_refused(self):
        for path in (f"{self.install}/blindfold/rules.py", f"{self.config}/config.json", f"{self.link}/SKILL.md",
                     f"{self.home_form}/bin/blindfold", f"{self.install}/../install/x"):
            with self.subTest(path=path):
                self.assertTrue(self.reason({"file_path": path, "content": "x"}))
                self.assertTrue(self.reason({"path": path, "old_string": "a", "new_string": "b"}))

    def test_other_writes_and_any_reads_are_fine(self):
        self.assertIsNone(self.reason({"file_path": f"{self.root}/elsewhere.py", "content": "x"}))
        self.assertIsNone(self.reason({"file_path": f"{self.install}/blindfold/rules.py"}, read_only=True))

    def test_settings_edits_are_refused_only_when_they_touch_blindfold(self):
        self.assertTrue(self.reason({"file_path": self.settings, "old_string": f'"{self.install}/bin/blindfold hook"', "new_string": '""'}))
        self.assertTrue(self.reason({"file_path": self.settings, "edits": [{"old_string": "blindfold hook", "new_string": ""}]}))
        self.assertTrue(self.reason({"file_path": self.settings, "content": json.dumps({"permissions": {}})}))
        self.assertIsNone(self.reason({"file_path": self.settings, "old_string": '"allow": []', "new_string": '"allow": ["Read"]'}))
        with open(self.settings) as handle:
            kept = handle.read().replace('"allow": []', '"allow": ["Read"]')
        self.assertIsNone(self.reason({"file_path": self.settings, "content": kept}))

    def test_the_hook_off_setting_is_refused_in_any_settings_file_and_any_shell_write(self):
        key = "disable" + "AllHooks"
        for path in (f"{self.root}/x/.claude/managed-settings.json", f"{self.root}/Settings.JSON", f"{self.root}/p/.claude/x.json"):
            with self.subTest(path=path):
                self.assertTrue(self.reason({"file_path": path, "content": f'{{"{key.lower()}": true}}'}))
        self.assertIsNone(self.reason({"file_path": f"{self.root}/notes.md", "content": f"Never set {key}."}))
        self.assertTrue(self.reason({"command": f"jq '.{key} = true' a.json > b.json"}))
        self.assertTrue(self.reason({"command": f"python3 -c 'print(\"{key}\")'"}))
        self.assertIsNone(self.reason({"command": f"cat >> notes.md <<'EOF'\nNever set {key}.\nEOF"}))
        self.assertIsNone(self.reason({"command": f"grep -rn {key} ."}))

    def test_turning_hooks_off_is_refused_anywhere(self):
        self.assertTrue(self.reason({"file_path": f"{self.root}/proj/.claude/settings.json", "content": '{"disableAllHooks": true}'}))
        key = "disable" + "AllHooks"
        self.assertTrue(self.reason({"command": f"jq '.{key} = true' {self.settings} > t && mv t {self.settings}"}))
        self.assertTrue(self.reason({"command": f"echo '{{\"{key}\": true}}' > proj/.claude/settings.json"}))
        self.assertIsNone(self.reason({"command": f"grep -rn disableAllHooks {self.root}"}))

    def test_commands_that_could_change_blindfold_are_refused(self):
        install, home_form = self.install, self.home_form
        dollar_home = "$HOME" + home_form[1:]
        for command in (
            f"git -C {install} pull", f"git -C {home_form} checkout -- blindfold", f"rm -rf {dollar_home}",
            f"find {install} -name '*.pyc' | xargs rm", f"ls {install} | while read f; do rm $f; done", f"{install}/bin/blindfold install --apply",
            f"cd {install} && make", f"echo $(cat {install}/x)", f"sed -i '' 's/a/b/' {self.config}/config.json",
            f"chmod -R u+w {install}", f"find {install} -name '*.py' -delete", f"cp evil.py {self.link}/x.py",
            f"sed -i '' '/blindfold/d' {self.settings}", f"cat > {self.settings} <<'EOF'\n{{\"permissions\": {{}}}}\nEOF",
            f"python3 -c 'print(1)' > {self.settings}", f'grep x {install}/y "$(rm -rf {install})"',
            f"grep 'unbalanced {install}/y > z",
        ):
            with self.subTest(command=command):
                self.assertTrue(self.reason({"command": command}))

    def test_read_only_commands_are_fine(self):
        install = self.install
        for command in (
            f"git -C {install} log --oneline -3", f"ls -la {install}", f"cat {install}/README.md 2>/dev/null",
            f"grep -rn rule {install}/blindfold | head -5", f"{install}/bin/blindfold doctor", f"{install}/bin/blindfold install",
            f"echo '{{}}' | {install}/bin/blindfold hook", f"cd {install} && git status", f"wc -l {self.config}/config.json 2>&1",
            f"jq . {self.settings}", "rm -rf build/",
            f'{install}/bin/blindfold selftest --installed --agent claude 2>&1 | grep -E "hooks run|PASS|FAIL"',
            f"grep -n 'a > b; c' {install}/x", f"cat {install}/x > /tmp/y", f"cat {install}/x '|' > out", f'grep "say \\"hi\\" | there" {install}/x',
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.reason({"command": command}))

    def test_notes_that_mention_a_protected_path_are_not_uses(self):
        install = self.install
        for command in (
            f"cat >> notes.md <<'EOF'\nUpdate with: git -C {install} pull\nEOF",
            f"echo 'installed at {install}' > /tmp/where.txt",
            f"printf '%s\\n' {install} >> log.txt",
        ):
            with self.subTest(command=command[:40]):
                self.assertIsNone(self.reason({"command": command}))

    def test_but_writing_into_one_or_running_code_that_names_one_is_refused(self):
        install = self.install
        for command in (
            f"cat > {install}/blindfold/rules.py <<'EOF'\nx = 1\nEOF",
            f"echo x | tee {install}/x",
            f"python3 - <<'EOF'\nopen('{install}/x', 'w').write('')\nEOF",
            f"node -e \"require('fs').rmSync('{install}', {{recursive: true}})\"",
            f"cd {install}; rm -rf blindfold", f"cd /tmp && cd {install} && git reset --hard",
            f"cat >> notes.md <<EOF\n$(rm -rf {install})\nEOF",
        ):
            with self.subTest(command=command[:40]):
                self.assertTrue(self.reason({"command": command}))
        # Deny by default: a command that names a protected path may only read or write notes elsewhere.
        self.assertTrue(self.reason({"command": f"cd {install} && cd /tmp && rm -rf scratch"}))

    def test_a_note_naming_a_path_then_a_check_that_reads_it_is_fine(self):
        command = f"cat >> notes.md <<'EOF'\nUpdate: git -C {self.install} pull\nEOF\necho \"lines: $(wc -l < notes.md)\""
        self.assertIsNone(self.reason({"command": command}))
        written_then_run = f"cat > x.sh <<'EOF'\nrm -rf {self.install}\nEOF\nbash x.sh"
        self.assertTrue(self.reason({"command": written_then_run}))
        self.assertTrue(self.reason({"command": f"echo 'rm -rf {self.install}' > x.sh; bash x.sh"}))

    def test_cd_targets_that_cannot_be_followed(self):
        install = self.install
        self.assertTrue(self.reason({"command": f'cd "$(dirname {install})/install" && rm x'}))
        self.assertTrue(self.reason({"command": "cd install && cd /tmp && cd - && rm x"}, cwd=self.root))
        self.assertTrue(self.reason({"command": f"cd '{install}' && rm x"}))
        self.assertIsNone(self.reason({"command": 'cd "$(git rev-parse --show-toplevel)" && make'}))

    def test_the_hook_off_setting_written_in_two_steps_is_refused(self):
        key = "disable" + "AllHooks"
        command = f"printf '{{\"{key}\": true}}' > /tmp/s.json && cp /tmp/s.json proj/.claude/settings.json"
        self.assertTrue(self.reason({"command": command}))

    def test_indirection_and_relative_paths_are_followed(self):
        install, rel = self.install, self.install[len(os.path.expanduser("~")) + 1 :]
        for command, cwd in (
            (f"cd $HOME/{rel} && rm -rf blindfold", None),
            (f"cd ${{HOME}}/{rel}; git pull", None),
            (f"cd {os.path.basename(install)} && rm x", self.root),
            ("cd .. && cd install && rm x", os.path.join(install, "blindfold")),
            ("echo x > notes.md", install),
            (f"X={install}; rm -rf $X", None),
            (f"echo {install} | sh", None),
            (f"cat > /dev/stdout <<'EOF'\n{install}\nEOF", None),
            (f"echo hi > >(tee {install}/x)", None),
        ):
            with self.subTest(command=command[:40]):
                self.assertTrue(self.reason({"command": command}, cwd=cwd))
        self.assertIsNone(self.reason({"command": "cd build && make"}, cwd=self.root))

    def test_a_command_run_inside_a_protected_path_is_judged_by_its_cwd(self):
        self.assertTrue(self.reason({"command": "git pull"}, cwd=self.install))
        self.assertTrue(self.reason({"command": "rm -rf blindfold"}, cwd=os.path.join(self.link)))
        self.assertIsNone(self.reason({"command": "git log -1"}, cwd=self.install))

    def test_the_hook_denies_with_a_reason_that_hands_the_change_to_the_user(self):
        from unittest import mock

        with mock.patch.object(selfguard, "PROTECTED", [self.install]):
            out = reply({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": self.root,
                         "tool_input": {"command": f"git -C {self.install} pull"}}, Masker(key=b"k" * 32))
        decision = out["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("! <command>", decision["permissionDecisionReason"])


if __name__ == "__main__":
    unittest.main()
