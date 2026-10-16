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
    found: List[str] = []
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
            found.append("".join(current))
            current = []
            at = _consume_bodies(command, at + 1, pending, found)
            pending = []
            continue
        separator = next((s for s in _SEPARATORS if command.startswith(s, at)), None)
        if separator:
            found.append("".join(current))
            current = []
            at += len(separator)
            continue
        current.append(char)
        at += 1
    found.append("".join(current))
    return [part for part in (p.strip() for p in found) if part]


def _consume_bodies(command: str, at: int, pending: List[Tuple[bool, str, int]], found: List[str]) -> int:
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
        found[opener] = found[opener].rstrip(" \t") + "".join(body)
    return at


def head(part: str) -> str:
    """The command word of a part, past VAR=value assignments."""
    words = part.split()
    while words and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words = words[1:]
    return words[0].rsplit("/", 1)[-1] if words else ""


def first_line(part: str) -> str:
    return part.split("\n", 1)[0]


def writes_heredoc_to_file(part: str) -> bool:
    """cat or tee saving a here-document to a file: its body is data, not
    commands. Piped on (`cat <<EOF | sh`) it may be run, so it isn't."""
    line = first_line(part)
    return head(line) in ("cat", "tee") and bool(_HEREDOC.search(line)) and bool(write_targets(part))


def strip_data_heredocs(command: str) -> str:
    """The command without the bodies of here-documents saved to files."""
    return "\n".join(first_line(part) if writes_heredoc_to_file(part) else part for part in parts(command))


def write_targets(part: str) -> List[str]:
    """Files a data command writes: redirect targets and tee's arguments."""
    line = first_line(part)
    targets = re.findall(r"(?<![<\d&])\d?>{1,2}\|?[ \t]*([^\s;&|<>]+)", line)
    if head(line) == "tee":
        targets += [word for word in line.split()[1:] if not word.startswith(("-", ">", "<"))]
    return [target.strip("'\"") for target in targets if target not in ("/dev/null", "&1", "&2")]
