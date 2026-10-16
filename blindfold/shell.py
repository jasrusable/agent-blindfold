"""Just enough shell syntax to judge a command's parts.

Not a parser: it knows quotes, escapes, here-documents and the separators
(; && || | newline), which is what telling a written-down mention from a real
use needs. Anything it doesn't understand stays in place, where the callers
treat it as unsafe.
"""

import re
from typing import List, Tuple

_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_SEPARATORS = ("&&", "||", ";", "|", "\n")
DATA_COMMANDS = ("cat", "tee", "echo", "printf")


def parts(command: str) -> List[str]:
    """The command's parts, split at separators outside quotes. A here-document's
    body goes with the part that opened it."""
    return [part for part, _ in split(command)]


def split(command: str) -> List[Tuple[str, str]]:
    """(part, the separator after it) pairs; see parts()."""
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
            found.append(["".join(current), "\n"])
            current = []
            at = _consume_bodies(command, at + 1, pending, found)
            pending = []
            continue
        separator = next((s for s in _SEPARATORS if command.startswith(s, at)), None)
        if separator:
            found.append(["".join(current), separator])
            current = []
            at += len(separator)
            continue
        current.append(char)
        at += 1
    found.append(["".join(current), ""])
    return [(part.strip(), separator) for part, separator in found if part.strip()]


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
        found[opener][0] = found[opener][0].rstrip(" \t") + "".join(body)
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
_READERS = {"wc", "cat", "head", "tail", "grep", "egrep", "less", "ls", "stat", "file", "diff", "md5", "shasum", "test", "["}
_GIT_READS = {"add", "diff", "status", "log", "show"}
_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def is_plain_file(target: str) -> bool:
    """A file on disk, named in plain path characters: not a device,
    descriptor, glob, brace or other expansion that could go anywhere."""
    return bool(_PLAIN_PATH.fullmatch(target)) and not target.startswith(("/dev/", "/proc/"))


def _only_reads(command: str, name: str, piped_on: bool) -> bool:
    words = command.split()
    while words and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words = words[1:]
    verb = words[0].rsplit("/", 1)[-1] if words else ""
    reads = verb in _READERS or (verb == "git" and any(w in _GIT_READS for w in words[1:3]))
    return reads and not piped_on and not re.search(r"(?:^|\s)[<>]", command.replace(f"< {name}", "").replace(f"<{name}", ""))


def runs_file(later: List[Tuple[str, str]], path: str) -> bool:
    """Whether a later part may run the file at path: anything that names it
    except a plain read (wc -l < x, cat x, git add x), also inside $(…)."""
    name = path.rsplit("/", 1)[-1]
    if not name:
        return True
    for part, separator in later:
        if name not in part:
            continue
        outer = part
        for match in _SUBSTITUTION.finditer(part):
            inner = match.group(1) if match.group(1) is not None else match.group(2)
            if name in inner and not _only_reads(inner.strip(), name, "|" in inner):
                return True
            outer = outer.replace(match.group(0), "")
        if name in outer and not _only_reads(first_line(outer), name, separator == "|"):
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
