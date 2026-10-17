"""Refuse tool calls that would change blindfold itself: the installed copy that
is running, its config and key, its skill links, its entries in the agents'
settings, or a switch that turns hooks off. An agent tidying settings, or a
stray git command, must not quietly turn masking off; the user makes those
changes. Like the command denylist, this guards against accidents, not intent,
and it judges writes, not mentions: reading blindfold's files is fine, and so is
text that names a path (a note, a heredoc, an issue body, a commit message).
"""

import functools
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import shell
from .cli_paths import REPO
from .config import CONFIG_DIR
from .shell import Word
from .structure import strings

PROTECTED = [
    REPO,
    CONFIG_DIR,
    "~/.claude/skills/blindfold",
    "~/.grok/skills/blindfold",
    "~/.grok/hooks/blindfold.json",
]
SETTINGS = ["~/.claude/settings.json", "~/.claude/settings.local.json"]
# Claude Code's setting that turns every hook off. Assembled, so this file
# doesn't trip an installed copy of this guard when it is edited.
DISABLE_HOOKS = "disable" + "AllHooks"

_PATH_KEYS = ("file_path", "filePath", "path", "target_file", "targetFile", "notebook_path")
_OLD_TEXT_KEYS = ("old_string", "oldString", "old_str")
_HOOK_COMMAND = re.compile(r"[^\s\"']*blindfold(?: [^\s\"']+){0,4} hook")
# Agent settings files, wherever they are: settings.json, settings.local.json,
# managed-settings.json, anything under a .claude directory.
_SETTINGS_FILE = re.compile(r"settings[^/]*\.json$|(?:^|/)\.claude/", re.IGNORECASE)

# How a command treats the paths it is given, once past sudo, env and the like.
# Readers only read them. Runners run code that can't be followed, so they may
# not even name a protected path. Writers may write any argument, copiers only
# their destination. Anything else may write any argument that is a path.
_READERS = frozenset(
    "ls cat head tail less more grep egrep fgrep rg wc stat file diff cmp readlink realpath test [ echo printf "
    "jq du md5 md5sum shasum sha256sum basename dirname pwd which type true false : read cut tr nl strings "
    "export declare local readonly unset set shopt setopt for select".split()
)
_RUNNERS = frozenset("sh bash zsh dash ksh fish csh tcsh eval source . xargs parallel awk gawk nawk mawk osascript alias".split())
_INTERPRETER = re.compile(r"(?:python|pypy|node|nodejs|deno|bun|perl|ruby|php|lua)[\d.]*")
_WRITERS = frozenset(
    "rm rmdir unlink shred truncate touch mkdir chmod chown chgrp chflags xattr setfacl tee mv patch "
    "vi vim nvim nano emacs ed ex code subl".split()
)
_COPIERS = frozenset("cp ln rsync install scp ditto".split())
_WRAPPERS = frozenset("sudo doas env command builtin exec nice nohup time timeout gtimeout caffeinate stdbuf unbuffer".split())
_KEYWORDS = frozenset("if then else elif fi do done while until { } ! esac".split())
_LAUNCHER_READS = ("doctor", "scan", "hook", "selftest")
_GIT_READS = frozenset(
    "status log show diff rev-parse describe ls-files ls-tree ls-remote blame grep cat-file rev-list shortlog "
    "show-ref for-each-ref name-rev merge-base whatchanged show-branch count-objects check-ignore check-attr var "
    "help version fetch".split()
)
# Flags that make branch, tag, remote, config and the like change something.
_GIT_CHANGES = frozenset(
    "-d -D -m -M -c -C -f --delete --move --copy --force -u --set-upstream-to --unset-upstream --edit-description "
    "--add --unset --unset-all --replace-all --rename-section --remove-section --edit -e".split()
)
_WRITE_OPS = frozenset((">", ">>", ">|", "&>", "&>>", "<>"))
_FIND_WRITES = ("-fprint", "-fprint0", "-fprintf", "-fls")
_FIND_RUNS = ("-exec", "-execdir", "-ok", "-okdir")
_OPTION_VALUE = re.compile(r"^-{1,2}[\w.-]+=")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_NUMBER = re.compile(r"\d+(?:\.\d+)?[smhd]?")
_SETTINGS_REASON = "it may rewrite the agent settings; use the file-edit tool, which checks blindfold's hooks stay"


@functools.lru_cache(maxsize=4096)
def _resolve(path: str) -> str:
    """Resolved once per path per hook run: a command can name many."""
    return os.path.realpath(os.path.expanduser(path))


def _inside(path: str, roots: Iterable[str]) -> Optional[str]:
    target = _resolve(path)
    return next((root for root in roots if target == _resolve(root) or target.startswith(_resolve(root) + os.sep)), None)


def _spellings(path: str) -> List[str]:
    """How a command might name path: absolute, ~/…, $HOME/…, ${HOME}/…"""
    absolute = _resolve(path)
    home = os.path.expanduser("~")
    forms = {absolute, os.path.abspath(os.path.expanduser(path))}
    for form in list(forms):
        if form.startswith(home + os.sep):
            rest = form[len(home):]
            forms |= {"~" + rest, "$HOME" + rest, "${HOME}" + rest}
    return sorted(forms)


def _named(text: str, roots: Iterable[str]) -> Optional[str]:
    return next((root for root in roots for form in _cached_spellings(root) if form in text), None)


_SPELLINGS: Dict[str, List[str]] = {}


def _cached_spellings(path: str) -> List[str]:
    """_spellings resolves symlinks; once per path per hook run is enough."""
    if path not in _SPELLINGS:
        _SPELLINGS[path] = _spellings(path)
    return _SPELLINGS[path]


# The directory after a cd we can't follow: maybe anywhere, so a relative path
# there counts as protected when the command names a protected path. (No cwd
# at all, None, is no information: relative paths aren't judged.)
_UNKNOWN = "<unknown directory>"


def _cd(words: List[Word], text: str, here: Optional[str], previous: Optional[str], protected: List[str]) -> Optional[str]:
    """The directory after `cd …`. A target that names a protected path, or
    contains one's folder name, counts as inside it however it's spelled; any
    other target that can't be followed is unknown."""
    targets = [word for word in words[1:] if not word.text.startswith("-") or word.text == "-"]
    target = targets[0] if targets else Word(os.path.expanduser("~"))
    if target.text == "-":
        return previous or _UNKNOWN
    if target.dynamic:
        named = _named(text, protected) or next((root for root in protected if os.path.basename(_resolve(root)) in text), None)
        return _resolve(named) if named else _UNKNOWN
    if os.path.isabs(target.text):
        return os.path.normpath(target.text)
    return here if here in (None, _UNKNOWN) else os.path.normpath(os.path.join(here, target.text))


def _split_redirects(words: List[Word]) -> Tuple[List[Word], List[Word]]:
    """(the files redirections write, the remaining words). Input redirections
    and here-document delimiters are dropped; `>&2` duplicates a descriptor."""
    targets: List[Word] = []
    rest: List[Word] = []
    pending: Optional[str] = None
    for word in words:
        if pending is not None:
            duplicate = pending in (">&", "<&") and (word.text.isdigit() or word.text == "-")
            if (pending in _WRITE_OPS or pending == ">&") and not duplicate:
                targets.append(word)
            pending = None
        elif word.op:
            pending = word.text
        else:
            rest.append(word)
    return targets, rest


def _command(words: List[Word]) -> Tuple[List[Word], int, int]:
    """The command word and its arguments, past assignments, keywords and
    wrappers (sudo, env -i, timeout 5, …), plus how many subshell parentheses
    the part opens and closes."""
    opened = closed = 0
    while words and words[0].text.startswith("(") and not words[0].dynamic:
        stripped = words[0].text.lstrip("(")
        opened += len(words[0].text) - len(stripped)
        words = ([words[0]._replace(text=stripped)] if stripped else []) + words[1:]
    while words and words[-1].text.count(")") > words[-1].text.count("("):
        last = words[-1].text
        excess = last.count(")") - last.count("(")
        closed += excess
        words = words[:-1] + ([words[-1]._replace(text=last[:-excess])] if last[:-excess] else [])
    wrapped = False
    while words:
        text = words[0].text
        skip = not text or _ASSIGNMENT.match(text) or text in _KEYWORDS or (
            wrapped and (text.startswith("-") or _NUMBER.fullmatch(text))
        )
        if not skip and text in _WRAPPERS:
            wrapped = skip = True
        if not skip:
            break
        words = words[1:]
    return words, opened, closed


def _kind(words: List[Word]) -> str:
    """How the command treats its arguments (see _READERS)."""
    if not words:
        return "none"
    name = words[0].text.rsplit("/", 1)[-1]
    texts = [word.text for word in words[1:]]
    if name == "blindfold":
        first = [text for text in texts if not text.startswith("-")][:1]
        reads = first and (first[0] in _LAUNCHER_READS or (first[0] == "install" and "--apply" not in texts))
        return "launcher" if reads else "other"
    if name == "sed":
        return "writer" if any(re.match(r"-[A-Za-z]*i|--in-place", text) for text in texts) else "reader"
    if name == "find":
        return "runner" if set(texts) & set(_FIND_RUNS) else "find"
    if name in ("cd", "git", "dd"):
        return name
    if name in _READERS:
        return "reader"
    if name in _RUNNERS or _INTERPRETER.fullmatch(name):
        return "runner"
    return "writer" if name in _WRITERS else "copier" if name in _COPIERS else "other"


def _git(args: List[Word]) -> Tuple[bool, List[Word], List[Word]]:
    """(only reads, the repositories it names with -C and the like, its subcommand's arguments)."""
    rest, repos, risky = list(args), [], False
    while rest and rest[0].text.startswith("-"):
        option = rest.pop(0)
        name, _, value = option.text.partition("=")
        if name in ("-C", "--git-dir", "--work-tree"):
            repos += [option] if value else rest[:1]
            rest = rest if value else rest[1:]
        elif name in ("-c", "--config-env", "--exec-path", "--namespace"):
            # -c can set an alias, a pager or the hooks path: not a plain read.
            risky = True
            rest = rest if value or name == "--exec-path" else rest[1:]
    sub, sub_args = (rest[0].text, [word.text for word in rest[1:]]) if rest else ("", [])
    return not risky and _git_reads(sub, sub_args), repos, rest[1:]


def _git_reads(sub: str, args: List[str]) -> bool:
    flags = {arg for arg in args if arg.startswith("-")}
    first = [arg for arg in args if not arg.startswith("-")][:1]
    if sub in _GIT_READS:
        return True
    if flags & _GIT_CHANGES:
        return False
    return {
        "branch": not first,
        "tag": not first,
        "remote": first in ([], ["show"], ["get-url"]),
        "config": bool(flags & {"--get", "--get-all", "--get-regexp", "--list", "-l"}) or first in (["get"], ["list"]),
        "stash": first in (["list"], ["show"]),
        "worktree": first == ["list"],
        "reflog": first in ([], ["show"]),
        "submodule": first == ["status"],
        "notes": first in (["list"], ["show"]),
    }.get(sub, False)


def _targets(kind: str, words: List[Word]) -> List[Word]:
    """The words a command may write to."""
    args = words[1:]
    positional = [word for word in args if not word.text.startswith("-")]
    if kind == "writer":
        return positional
    if kind == "copier":
        explicit = [after for word, after in zip(args, args[1:]) if word.text in ("-t", "--target-directory")]
        explicit += [word for word in args if word.text.startswith("--target-directory=")]
        return explicit or positional[-1:]
    if kind == "dd":
        return [word._replace(text=word.text[3:], prefix=word.prefix[3:]) for word in args if word.text.startswith("of=")]
    if kind == "find":
        starts = args[: next((i for i, word in enumerate(args) if word.text[:1] in "-(!"), len(args))]
        written = [after for word, after in zip(args, args[1:]) if word.text in _FIND_WRITES]
        return written + (starts if any(word.text == "-delete" for word in args) else [])
    if kind == "other":
        # The command word too (running a file from a protected path). Words
        # with spaces are text (a message, a body), not paths.
        return [word for word in words if not any(char.isspace() for char in word.text)]
    return []


def _root(word: Word, here: Optional[str], guarded: List[str], named: Optional[str]) -> Optional[str]:
    """The guarded path a word names as a file, if any. A word the shell
    still expands counts when its literal start leads into one, or when the
    command names one anywhere (X=<path>; rm -rf $X)."""
    if word.dynamic:
        return _root_of_prefix(_OPTION_VALUE.sub("", word.prefix, count=1), here, guarded) or named
    text = _OPTION_VALUE.sub("", word.text, count=1)
    if not text or text.startswith("-"):
        return None
    if not os.path.isabs(text):
        if here in (None, _UNKNOWN):
            return named if here == _UNKNOWN else None
        text = os.path.join(here, text)
    return _inside(text, guarded)


def _root_of_prefix(prefix: str, here: Optional[str], guarded: List[str]) -> Optional[str]:
    """A guarded path the literal start of an expanding word may lead into
    (~/.config/$X, ~/.local/share/agent-*). Not home or above: ~/$X would match
    everything."""
    if not prefix or (here in (None, _UNKNOWN) and not os.path.isabs(prefix)):
        return None
    resolved = _resolve(os.path.join(here or "", prefix))
    if os.path.expanduser("~").startswith(resolved):
        return None
    stem = resolved + os.sep if prefix.endswith("/") else resolved
    return next((root for root in guarded if (_resolve(root) + os.sep).startswith(stem)), None) or _inside(resolved, guarded)


def _why(root: str, settings: List[str]) -> str:
    return _SETTINGS_REASON if root in settings else f"it changes {root}"


def _pipelines(segments: List[Tuple[str, str, str]]) -> List[str]:
    """For each part, the text of the whole pipeline it is in: what a runner
    reads on stdin comes from the parts before it."""
    groups: List[List[int]] = [[]]
    for index, (_, _, separator) in enumerate(segments):
        groups[-1].append(index)
        if separator != "|":
            groups.append([])
    text = {index: "\n".join(segments[i][0] + segments[i][1] for i in group) for group in groups for index in group}
    return [text[index] for index in range(len(segments))]


def _command_reason(command: str, cwd: Optional[str], protected: List[str], settings: List[str]) -> Optional[str]:
    """Refuse a command that writes to a protected path or the agent settings:
    a redirection, a writer's argument, a copier's destination, a git command
    that changes a repository there, anything but a read run inside one, a file
    run from one. A runner (a shell, Python, xargs, …), a substitution or a
    part that can't be parsed may not even name one, since what it does can't
    be followed. Text is data: a heredoc saved or piped to a command that
    doesn't run it, a quoted message, a word with spaces."""
    guarded = protected + settings
    segments = shell.segments(shell.inline_literal_heredocs(command))
    pairs = [(text + body, separator) for text, body, separator in segments]
    pipelines = _pipelines(segments)
    named = next(filter(None, (_named(text, guarded) for text, _, _ in segments)), None)
    here, previous, scopes, key_written = cwd, None, [], False
    for index, (text, body, _) in enumerate(segments):
        parsed = shell.words(text)
        if parsed is None:
            unclear = _named(text + body, guarded)
            if unclear:
                return _why(unclear, settings)
            continue
        redirects, rest = _split_redirects(parsed[0])
        words, opened, closed = _command(rest)
        scopes += [here] * opened
        kind = _kind(words)
        if kind == "cd":
            here, previous = _cd(words, text, here, previous, protected), here
        git_reads, repos, git_args = _git(words[1:]) if kind == "git" else (False, [], [])
        reads = kind in ("cd", "reader", "launcher", "find", "none") or git_reads
        runs = kind == "runner" or parsed[1] or shell.body_substitutes(text, body)
        unclear = _named(pipelines[index] if kind == "runner" else text + body, guarded) if runs else None
        if unclear:
            return _why(unclear, settings)
        if kind == "git" and not git_reads:
            changed = [word for word in git_args if os.path.isabs(word.text) or word.dynamic]
            # No -C: the repository it is in, which may be anywhere after a cd it can't follow.
            current = [] if here is None else [Word("", dynamic=True)] if here == _UNKNOWN else [Word(here)]
            redirects = redirects + changed + (repos or current)
        for word in redirects + _targets(kind, words):
            root = _root(word, here, guarded, named)
            if root:
                return _why(root, settings)
        inside = None if reads or here in (None, _UNKNOWN) else _inside(here, protected)
        if inside:
            return f"it runs inside {inside}"
        tee = words[0].text == "tee" if words else False
        written = [word.text for word in redirects + (_targets("writer", words) if tee else [])]
        later = pairs[index + 1 :]
        mentioned = _named(text + body, guarded)
        if mentioned and any(shell.runs_file(later, path) for path in written):
            return f"it writes a file that names {mentioned} and then runs it"
        if not reads or redirects:
            if key_written:
                return f"it writes {DISABLE_HOOKS} and then runs more"
            if DISABLE_HOOKS.lower() in (text + body).lower():
                data = (
                    bool(words) and words[0].text in shell.DATA_COMMANDS and bool(written) and not runs
                    and all(shell.is_plain_file(path) and not _SETTINGS_FILE.search(path) for path in written)
                    and not any(shell.runs_file(later, path) for path in written)
                )
                if not data:
                    return f"it sets {DISABLE_HOOKS}"
                key_written = True
        for _ in range(min(closed, len(scopes))):
            here = scopes.pop()
    return None


def _hook_commands(text: str) -> set:
    return set(_HOOK_COMMAND.findall(text))


def _read(path: str) -> str:
    try:
        with open(_resolve(path), encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _values_under(value: Any, key: str) -> List[Any]:
    found, stack = [], [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            found += [item for name, item in node.items() if name == key]
            stack += list(node.values())
        elif isinstance(node, list):
            stack += node
    return found


def _settings_change(tool_input: Dict[str, Any], path: str) -> bool:
    """An edit that touches blindfold's hook entries, or a full write that drops them."""
    if "content" in tool_input:
        return bool(_hook_commands(_read(path)) - _hook_commands(str(tool_input["content"])))
    old_texts = [text for key in _OLD_TEXT_KEYS for text in strings(_values_under(tool_input, key))]
    return any("blindfold" in text for text in old_texts)


def reason(
    tool_input: Any, read_only_tool: bool, cwd: Optional[str] = None,
    protected: Optional[List[str]] = None, settings: Optional[List[str]] = None,
) -> Optional[str]:
    """Why this call would change blindfold itself, or None."""
    protected = PROTECTED if protected is None else protected
    settings = SETTINGS if settings is None else settings
    if read_only_tool or not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if isinstance(command, str):
        return _command_reason(command, cwd, protected, settings)
    paths = [value for key in _PATH_KEYS for value in [tool_input.get(key)] if isinstance(value, str) and value]
    for path in paths:
        root = _inside(path, protected)
        if root:
            return f"it writes inside {root}"
        if _SETTINGS_FILE.search(path) and any(DISABLE_HOOKS.lower() in text.lower() for text in strings(tool_input)):
            return f"it sets {DISABLE_HOOKS}"
        if _inside(path, settings) and _settings_change(tool_input, path):
            return "it changes blindfold's hooks in the agent settings"
    return None
