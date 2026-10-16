"""The small shell model the guards use to tell a mention from a use."""

import unittest

from blindfold import shell
from blindfold.mask import Masker

from .helpers import reply

OP = "o" + "p"
M = Masker(key=b"s" * 32)


def denied(command, tool="Bash", **extra):
    out = reply({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": command, **extra}}, M)
    return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


class Parts(unittest.TestCase):
    def test_separators_split_outside_quotes_only(self):
        self.assertEqual(shell.parts("a && b || c; d | e\nf"), ["a", "b", "c", "d", "e", "f"])
        self.assertEqual(shell.parts('grep -E "a|b; c" x | wc -l'), ['grep -E "a|b; c" x', "wc -l"])
        self.assertEqual(shell.parts("echo 'x && y' ; ls"), ["echo 'x && y'", "ls"])
        self.assertEqual(shell.parts(r"echo a\;b"), [r"echo a\;b"])

    def test_a_heredoc_body_stays_with_its_command(self):
        command = "cat > notes.md <<'EOF'\nline one; with | separators\nEOF\nls"
        self.assertEqual(shell.parts(command), ["cat > notes.md <<'EOF'\nline one; with | separators\nEOF", "ls"])
        chained = "cat > a.md <<EOF && echo done\nbody\nEOF"
        self.assertEqual(shell.parts(chained), ["cat > a.md <<EOF\nbody\nEOF", "echo done"])
        two = "cat > a <<A; cat > b <<B\none\nA\ntwo\nB"
        self.assertEqual(shell.parts(two), ["cat > a <<A\none\nA", "cat > b <<B\ntwo\nB"])
        tabbed = "cat <<-END\n\tbody\n\tEND\necho done"
        self.assertEqual(shell.parts(tabbed)[-1], "echo done")

    def test_an_unterminated_heredoc_keeps_the_rest_with_it(self):
        self.assertEqual(len(shell.parts("python3 - <<EOF\nimport os\nos.remove('x')")), 1)

    def test_substitution_in_a_heredoc_body_runs_only_without_a_quoted_delimiter(self):
        self.assertTrue(shell.runs_substitution("cat > a <<EOF\n$(x)\nEOF"))
        self.assertTrue(shell.runs_substitution("cat > a <<-EOF\n\t`x`\n\tEOF"))
        self.assertFalse(shell.runs_substitution("cat > a <<'EOF'\n$(x)\nEOF"))
        self.assertFalse(shell.runs_substitution('cat > a <<"EOF"\n`x`\nEOF'))
        self.assertTrue(shell.runs_substitution("echo $(x) > a"))

    def test_any_unquoted_opener_makes_a_body_expand(self):
        self.assertTrue(shell.runs_substitution("cat <<'A' <<B\n$(x)\nA\nB"))

    def test_plain_files_are_spelled_in_plain_path_characters(self):
        for target in ("notes.md", "~/notes.md", "/tmp/a-b_c.txt", "out/x,y=1.log"):
            self.assertTrue(shell.is_plain_file(target), target)
        for target in ("{a,b}", "x[1]", "~root/x", "!x", "/dev/stdout", "/proc/1/fd/1", "*.md", "$OUT"):
            self.assertFalse(shell.is_plain_file(target), target)

    def test_a_later_part_runs_a_file_only_through_a_runner(self):
        for later in ("bash x.sh", "sh -e ./x.sh", ". ./x.sh", "source x.sh", "./x.sh", "python3 x.sh",
                      "echo $(sh x.sh)", "env FOO=1 bash x.sh"):
            self.assertTrue(shell.runs_file(later, "x.sh"), later)
        for later in ("wc -l < x.sh", "cat x.sh", "git add x.sh", "echo done", "bash y.sh", "ls x.sh.bak"):
            self.assertFalse(shell.runs_file(later, "x.sh"), later)

    def test_heads_and_write_targets(self):
        self.assertEqual(shell.head("A=1 B=2 /usr/bin/env python3 x"), "env")
        self.assertEqual(shell.write_targets("cat > a.txt 2>/dev/null"), ["a.txt"])
        self.assertEqual(shell.write_targets("echo x >> out.log 2>&1"), ["out.log"])
        self.assertEqual(shell.write_targets("cat x | tee -a out.log"), [])
        self.assertEqual(shell.write_targets("tee -a out.log"), ["out.log"])


class MentionsAreNotUses(unittest.TestCase):
    def test_a_secret_dump_command_written_into_a_doc_is_fine(self):
        self.assertFalse(denied(f"cat > docs/x.md <<'EOF'\nNever run `{OP} read op://V/i/f` in scripts.\nEOF"))
        self.assertFalse(denied(f"tee -a notes.txt <<EOF\n{OP} read is refused\nEOF"))

    def test_the_same_text_fed_to_a_shell_or_substituted_is_refused(self):
        self.assertTrue(denied(f"bash <<'EOF'\n{OP} read op://V/i/f\nEOF"))
        self.assertTrue(denied(f"cat <<EOF | sh\n{OP} read op://V/i/f\nEOF"))
        self.assertTrue(denied(f"cat <<EOF\n{OP} read op://V/i/f\nEOF"))
        # An unquoted heredoc expands $(…) and `…` in its body, even when saved to a file.
        self.assertTrue(denied(f"cat > notes.md <<EOF\nkey: $({OP} read op://V/i/f)\nEOF"))
        self.assertTrue(denied(f"tee notes.md <<EOF\nkey: `{OP} read op://V/i/f`\nEOF"))
        self.assertFalse(denied(f"cat > notes.md <<'EOF'\nkey: $({OP} read op://V/i/f)\nEOF"))
        # Saved, then run; or written to a device, not a file.
        self.assertTrue(denied(f"cat > x.sh <<'EOF'\n{OP} read op://V/i/f\nEOF\nbash x.sh"))
        self.assertTrue(denied(f"cat > /dev/stdout <<'EOF'\n{OP} read op://V/i/f\nEOF"))
        self.assertTrue(denied(f"tee x.md <<'EOF' | bash\n{OP} read op://V/i/f\nEOF"))
        self.assertTrue(denied(f"cat > x.py <<'EOF'\n{OP} read op://V/i/f\nEOF\npython3 x.py"))
        self.assertTrue(denied(f"cat > x.sh <<'EOF'\n{OP} read op://V/i/f\nEOF\necho $(sh x.sh)"))

    def test_a_note_followed_by_a_check_that_reads_it_is_fine(self):
        self.assertFalse(denied(f"cat >> notes.md <<'EOF'\nNever run `{OP} read op://V/i/f`.\nEOF\necho \"lines: $(wc -l < notes.md)\""))
        self.assertTrue(denied(f'git commit -m "use `{OP} read op://V/i/f`"'))

    def test_an_example_placeholder_may_go_into_docs_but_not_into_code_or_config(self):
        example = "<" + "blindfold kind=env:STRIPE_API_KEY len=107 id=3f9a1c>"

        def write(path):
            out = reply({"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": path, "content": example}}, M)
            return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

        self.assertFalse(write("/w/README.md"))
        self.assertFalse(write("/w/docs/guide.mdx"))
        for path in ("/w/.env", "/w/config.ts", "/w/notes.txt"):
            self.assertTrue(write(path), path)
        self.assertTrue(denied(f"echo '{example}' > README.md"))


if __name__ == "__main__":
    unittest.main()
