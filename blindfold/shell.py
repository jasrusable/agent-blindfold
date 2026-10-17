"""Just enough shell syntax to judge a command's parts.

Not a parser: it knows quotes, escapes, here-documents and the separators
(; && || | newline), which is what telling a written-down mention from a real
use needs. Anything it doesn't understand stays in place, where the callers
treat it as unsafe.
"""

import os
import re
from typing import List, NamedTuple, Optional, Tuple

_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_SEPARATORS = ("&&", "||", ";", "|", "\n")
DATA_COMMANDS = ("cat", "tee", "echo", "printf")


def parts(command: str) -> List[str]:
    """The command's parts, split at separators outside quotes. A here-document's
    body goes with the part that opened it."""
    return [part for part, _ in split(command)]


def split(command: str) -> List[Tuple[str, str]]:
    """(part, the separator after it) pairs; see parts()."""
    return [(text + body, separator) for text, body, separator in segments(command)]


def segments(command: str) -> List[Tuple[str, str, str]]:
    """(command text, its here-document bodies, the separator after it): the
    parts of split(), with the bodies kept apart from the text that runs."""
    found: List[List[str]] = []
    current: List[str] = []
    pending: List[Tuple[bool, str, int]] = []
    at, quote = 0, ""
    while at < len(command):
        char = command[at]
        if quote:
            current.append(char)
            if char == "\\" and quote == '"' and at + 1 < len(command):
                current.append(command[at + 1])
                at += 1
            elif char == quote:
                quote = ""
            at += 1
            continue
        heredoc = _HEREDOC.match(command, at) if char == "<" else None
        if heredoc:
            pending.append((heredoc.group(1) == "-", heredoc.group(3), len(found)))
            current.append(heredoc.group(0))
            at = heredoc.end()
            continue
        if char == "\\" and at + 1 < len(command):
            current.append(command[at : at + 2])
            at += 2
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            at += 1
            continue
        if char == "\n" and pending:
            found.append(["".join(current), "\n", ""])
            current = []
            at = _consume_bodies(command, at + 1, pending, found)
            pending = []
            continue
        separator = next((s for s in _SEPARATORS if command.startswith(s, at)), None)
        if separator:
            found.append(["".join(current), separator, ""])
            current = []
            at += len(separator)
            continue
        current.append(char)
        at += 1
    found.append(["".join(current), "", ""])
    return [(text.strip(), body.rstrip(), separator) for text, separator, body in found if text.strip()]


def _consume_bodies(command: str, at: int, pending: List[Tuple[bool, str, int]], found: List[List[str]]) -> int:
    """Append each pending here-document body (to its delimiter line) to the part that opened it."""
    for strip_tabs, delimiter, opener in pending:
        body = []
        while at < len(command):
            end = command.find("\n", at)
            line = command[at : end if end >= 0 else len(command)]
            at = end + 1 if end >= 0 else len(command)
            body.append("\n" + line)
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
        found[opener][2] += "".join(body)
    return at


def head(part: str) -> str:
    """The command word of a part, past VAR=value assignments."""
    words = part.split()
    while words and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words = words[1:]
    return words[0].rsplit("/", 1)[-1] if words else ""


def first_line(part: str) -> str:
    return part.split("\n", 1)[0]


def runs_substitution(part: str) -> bool:
    """Whether a part runs $(…) or `…`: on its command line, or in a
    here-document body whose delimiter isn't quoted (<<EOF expands; <<'EOF'
    doesn't)."""
    line, _, body = part.partition("\n")
    openers = list(_HEREDOC.finditer(line))
    expanding = not openers or any(not opener.group(2) for opener in openers)
    return any(mark in line or (expanding and mark in body) for mark in ("$(", "`", "<(", ">("))


_PLAIN_PATH = re.compile(r"(?:~/)?[A-Za-z0-9_./@%+,:=-]+")
# Commands that only read a file. A later part that names a written file any
# other way (sh x, cat x | sh, sh < x, cp x …) may run it.
_READERS = {"gh", "wc", "cat", "head", "tail", "grep", "egrep", "less", "ls", "stat", "file", "diff", "md5", "shasum", "test", "["}
_GIT_READS = {"add", "commit", "diff", "status", "log", "show"}


def is_plain_file(target: str) -> bool:
    """A file on disk, named in plain path characters: not a device,
    descriptor, glob, brace or other expansion that could go anywhere."""
    return bool(_PLAIN_PATH.fullmatch(target)) and not target.startswith(("/dev/", "/proc/"))


def _verb(command: str) -> Tuple[str, List[str]]:
    words = command.split()
    return (words[0].rsplit("/", 1)[-1] if words else ""), words


def _only_reads(command: str, name: str, piped_on: bool) -> bool:
    """A plain read of the file: a reader verb with no assignment prefix, no
    pipe onward and no redirect but `< file` (git: a read subcommand right
    after `git`, so no -c or --exec-path)."""
    verb, words = _verb(command)
    reads = verb in _READERS or (verb == "git" and len(words) > 1 and words[1] in _GIT_READS)
    if "<(" in command or ">(" in command:
        return False
    rest = re.sub(r"<\s*(?:~/)?[A-Za-z0-9_./@%+,:=-]*" + re.escape(name) + r"(?![\w.-])", "", command)
    return reads and not piped_on and not re.search(r"[<>]", rest)


def runs_file(later: List[Tuple[str, str]], path: str) -> bool:
    """Whether a later part may run the file at path: anything that names it
    except a plain read (wc -l < x, cat x, git add x). Inside a substitution
    its contents can end up anywhere (eval, printf -v, a pipe), so any
    substitution that names it counts as running it."""
    name = path.rsplit("/", 1)[-1]
    if not name:
        return True
    for part, separator in later:
        if name not in part:
            continue
        if any(mark in part for mark in ("$(", "`", "<(", ">(")):
            return True
        if not _only_reads(first_line(part), name, separator == "|"):
            return True
    return False


def writes_heredoc_to_file(part: str) -> bool:
    """cat or tee saving a here-document to plain files, running nothing: its
    body is data, not commands."""
    line = first_line(part)
    targets = write_targets(part)
    return (
        head(line) in ("cat", "tee") and bool(_HEREDOC.search(line)) and bool(targets)
        and all(is_plain_file(t) for t in targets) and not runs_substitution(part)
    )


def body_substitutes(text: str, body: str) -> bool:
    """Whether a here-document body runs $(…) or `…`: only when a delimiter
    isn't quoted (<<EOF expands; <<'EOF' doesn't)."""
    expanding = any(not opener.group(2) for opener in _HEREDOC.finditer(text))
    return expanding and any(mark in body for mark in ("$(", "`"))


def strip_data_heredocs(command: str) -> str:
    """The command without the bodies of here-documents saved to files. Not
    when piped on (`cat <<EOF | sh`), or when a later part runs the file it
    wrote (`cat > x.sh <<EOF … ; bash x.sh`): then the body may be run."""
    pairs = split(command)
    kept = []
    for index, (part, separator) in enumerate(pairs):
        data = writes_heredoc_to_file(part) and separator != "|"
        if data:
            data = not any(runs_file(pairs[index + 1 :], target) for target in write_targets(part))
        kept.append(first_line(part) if data else part)
    return "\n".join(kept)


def write_targets(part: str) -> List[str]:
    """Files a data command writes: redirect targets and tee's arguments."""
    line = first_line(part)
    targets = re.findall(r"(?<![<\d&])\d?>{1,2}\|?[ \t]*([^\s;&|<>]+)", line)
    if head(line) == "tee":
        targets += [word for word in line.split()[1:] if not word.startswith(("-", ">", "<"))]
    return [target.strip("'\"") for target in targets if target not in ("/dev/null", "&1", "&2")]


class Word(NamedTuple):
    """A word as the shell would pass it. op: a redirection operator. dynamic:
    the shell still expands it ($X, `…`, a glob or brace), and prefix is the
    literal text before that."""

    text: str
    op: bool = False
    dynamic: bool = False
    prefix: str = ""


_REDIRECT_OP = re.compile(r"&>>?|>>|>\||>&|<&|<<<|<<-?|<>|>|<")
_HOME_VAR = re.compile(r"\$(?:HOME\b|\{HOME\})")


def words(text: str) -> Optional[Tuple[List[Word], bool]]:
    """A command's words, unquoted the way the shell does: escapes and line
    continuations applied, ~ and $HOME expanded, comments dropped, redirection
    operators as words of their own. Also whether it runs a substitution
    ($(…), `…`, <(…), >(…)) outside single quotes. None when a quote is left
    open: the caller can't tell what runs."""
    home = os.path.expanduser("~")
    found: List[Word] = []
    current: List[str] = []
    state = {"started": False, "dynamic": False, "prefix": None, "substitutes": False}

    def mark_dynamic() -> None:
        if not state["dynamic"]:
            state["dynamic"], state["prefix"] = True, "".join(current)

    def flush() -> None:
        if state["started"]:
            found.append(Word("".join(current), False, state["dynamic"], state["prefix"] or ""))
        current.clear()
        state.update(started=False, dynamic=False, prefix=None)

    def dollar(at: int) -> int:
        """At a $: expand $HOME, mark anything else; returns the next index."""
        home_var = _HOME_VAR.match(text, at)
        if home_var:
            current.append(home)
            return home_var.end()
        if text.startswith("$(", at):
            state["substitutes"] = True
        mark_dynamic()
        current.append("$")
        return at + 1

    at = 0
    while at < len(text):
        char = text[at]
        if char in " \t\n":
            flush()
            at += 1
        elif char == "#" and not state["started"]:
            end = text.find("\n", at)
            at = len(text) if end < 0 else end
        elif char in "<>&":
            if char in "<>" and text.startswith("(", at + 1):
                state["substitutes"] = True
            if "".join(current).isdigit() and not state["dynamic"]:
                current.clear()
                state["started"] = False
            flush()
            operator = _REDIRECT_OP.match(text, at)
            if operator:
                found.append(Word(operator.group(0), op=True))
                at = operator.end()
            else:
                at += 1  # a lone &: runs in the background
        elif char == "\\":
            if text.startswith("\n", at + 1):
                at += 2
                continue
            current.append(text[at + 1 : at + 2])
            state["started"] = True
            at += 2
        elif char == "'":
            end = text.find("'", at + 1)
            if end < 0:
                return None
            current.append(text[at + 1 : end])
            state["started"] = True
            at = end + 1
        elif char == '"':
            state["started"] = True
            at += 1
            while at < len(text) and text[at] != '"':
                if text[at] == "\\" and at + 1 < len(text):
                    escaped = text[at + 1]
                    current.append("" if escaped == "\n" else escaped if escaped in '$`"\\' else "\\" + escaped)
                    at += 2
                elif text[at] == "$":
                    at = dollar(at)
                else:
                    if text[at] == "`":
                        state["substitutes"] = True
                        mark_dynamic()
                    current.append(text[at])
                    at += 1
            if at >= len(text):
                return None
            at += 1
        elif char == "$":
            state["started"] = True
            at = dollar(at)
        else:
            if char == "`":
                state["substitutes"] = True
            if char in "`*?[{":
                mark_dynamic()
            if char == "~" and not state["started"]:
                tilde_end = at + 1 == len(text) or text[at + 1] in "/ \t\n"
                current.append(home if tilde_end else "~")
                if not tilde_end:
                    mark_dynamic()
            else:
                current.append(char)
            state["started"] = True
            at += 1
    flush()
    return found, state["substitutes"]


# $(cat <<'EOF' … EOF): a quoted delimiter, so the body is literal text.
_LITERAL_HEREDOC = re.compile(
    r"(\"?)\$\(\s*cat\s*<<-?[ \t]*(['\"])([A-Za-z_][A-Za-z0-9_]*)\2[ \t]*\n(.*?)\n[ \t]*\3[ \t]*\n?\s*\)(\"?)",
    re.DOTALL,
)


def inline_literal_heredocs(command: str) -> str:
    """Each `$(cat <<'EOF' … EOF)` replaced by its body as one single-quoted
    word, which is what it expands to (`git commit -m "$(cat <<'EOF' …`). Only
    standing alone or as a whole double-quoted word: inside other quoted text
    it is left as it is, where the callers treat it as unclear."""

    def replace(match: "re.Match[str]") -> str:
        before, after = match.group(1), match.group(5)
        if before != after:
            return match.group(0)
        return "'" + match.group(4).replace("'", "'\\''") + "'"

    return _LITERAL_HEREDOC.sub(replace, command)
