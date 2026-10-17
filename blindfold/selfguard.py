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
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

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

# How a command treats the words it is given, once past sudo, env and the like.
# Readers only read, so they may name a protected path. Runners run code that
# can't be followed, so they may not name one anywhere, stdin included.
# Copiers write only their destination. Anything else may write: it may not
# name one in any word (git and gh messages excepted) or on its stdin, and its
# relative paths are followed.
_READERS = frozenset(
    "ls cat head tail grep egrep fgrep rg wc stat file diff cmp readlink realpath test [ echo printf jq du md5 "
    "md5sum shasum sha256sum basename dirname pwd which type true false : read cut tr nl strings shopt setopt "
    "for select".split()
)
_ASSIGNERS = frozenset("export declare local readonly typeset".split())
_RUNNERS = frozenset("sh bash zsh dash ksh fish csh tcsh eval source . xargs parallel awk gawk nawk mawk osascript alias".split())
_INTERPRETER = re.compile(r"(?:python|pypy|node|nodejs|deno|bun|perl|ruby|php|lua)[\d.]*")
_COPIERS = frozenset("cp ln install ditto".split())
# Wrappers run the command after their options; the options listed take a value.
_WRAPPERS = {
    "sudo": "-u -g -C -D -h -p -r -t -U -T --user --group --close-from --chdir --host --prompt --role --type "
            "--other-user --command-timeout",
    "doas": "-u -C",
    "env": "-u -C -S -P --unset --chdir --split-string",
    "nice": "-n --adjustment",
    "timeout": "-s -k --signal --kill-after",
    "gtimeout": "-s -k --signal --kill-after",
    "stdbuf": "-i -o -e --input --output --error",
    "caffeinate": "-t -w",
    "command": "", "builtin": "", "exec": "", "nohup": "", "time": "", "unbuffer": "",
}
_CHDIR = {"env": ("-C", "--chdir"), "sudo": ("-D", "--chdir")}
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
# Options that make even a reading subcommand write a file or run a program.
_GIT_RISKY = ("--output", "--upload-pack", "--receive-pack", "--exec", "-O", "--open-files-in-pager", "--ext-diff",
              "--textconv", "--filters", "-c", "--config-env")
# Variables git (or its pager and editor) runs or relocates by.
_RISKY_ENV = re.compile(r"(?:GIT_\w*|PAGER|EDITOR|VISUAL|LESSOPEN|LESSCLOSE)=")
# Variables that move where ~ and a relative cd lead.
_SHIFTING_ENV = re.compile(r"(?:^|[\s;&|(])(?:HOME|CDPATH)=")
# Message flags whose value is text, for the commands that take one. A file
# flag's value is text only when it isn't a protected path.
_MESSAGE_FLAGS = {
    "git": ("-m", "--message", "-F", "--file"),
    "gh": ("-t", "--title", "-b", "--body", "-F", "--body-file", "-n", "--notes", "--subject", "-f", "--raw-field",
           "-m", "--message"),
}
_GIT_MESSAGES = frozenset(("commit", "tag", "notes", "merge", "stash"))
_FILE_FLAGS = ("-F", "--file", "--body-file")
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


def _basename_in(text: str, protected: List[str]) -> Optional[str]:
    return next((root for root in protected if os.path.basename(_resolve(root)) in text), None)


def _cd(words: List[Word], text: str, here: Optional[str], previous: Optional[str], protected: List[str]) -> Optional[str]:
    """The directory after `cd …` or `pushd …`. A target that names a protected
    path, or contains one's folder name, counts as inside it however it's
    spelled; any other target that can't be followed is unknown."""
    targets = [word for word in words[1:] if not word.text.startswith("-") or word.text == "-"]
    target = targets[0] if targets else Word(os.path.expanduser("~"))
    if target.text == "-":
        return previous or _UNKNOWN
    if target.dynamic:
        named = _named(text, protected) or _basename_in(text, protected)
        return _resolve(named) if named else _UNKNOWN
    return _chdir(target, here)


def _chdir(target: Word, here: Optional[str]) -> Optional[str]:
    if target.dynamic:
        return _UNKNOWN
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


def _after(word: Word, cut: int) -> Word:
    """The word from index cut on: an option's attached value, a variable's value."""
    return word._replace(text=word.text[cut:], prefix=word.prefix[cut:] if word.dynamic else "")


class _Command(NamedTuple):
    """A part's command word and arguments, past what runs it."""

    words: List[Word]
    assignments: List[Word]  # FOO=bar before it or after env
    options: List[Word]  # wrappers' option values: sudo -u x, env -C dir
    chdir: Optional[Word]  # env -C, sudo -D
    runs: bool  # env -S: a whole command line in one word
    opened: int  # subshell parentheses it opens and closes
    closed: int


def _command(words: List[Word]) -> _Command:
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
    assignments: List[Word] = []
    options: List[Word] = []
    chdir: Optional[Word] = None
    runs, wrapper = False, ""
    while words:
        word, text = words[0], words[0].text
        words = words[1:]
        if not text or text in _KEYWORDS or (wrapper and _NUMBER.fullmatch(text)):
            continue
        if _ASSIGNMENT.match(text):
            assignments.append(word)
        elif wrapper and text.startswith("-"):
            long = text.startswith("--")
            flag, equals, _ = text.partition("=") if long else (text[:2], "", "")
            attached = len(flag) + 1 if long and equals else 2 if not long and len(text) > 2 else 0
            takes = not attached and flag in _WRAPPERS[wrapper].split() and bool(words)
            value = _after(word, attached) if attached else words[0] if takes else None
            words = words[1:] if takes else words
            if value is not None:
                options.append(value)
                chdir = value if flag in _CHDIR.get(wrapper, ()) else chdir
                runs = runs or (wrapper == "env" and flag in ("-S", "--split-string"))
        elif text in _WRAPPERS:
            wrapper = text
        else:
            words = [word] + words
            break
    return _Command(words, assignments, options, chdir, runs, opened, closed)


def _sed_kind(texts: List[str]) -> str:
    """sed only reads unless it edits in place, reads a script file, or its
    script may write or run (w, W, e: judged by the letters, so a script that
    merely contains one counts too)."""
    scripts: List[str] = []
    files: List[str] = []
    explicit, at = False, 0
    while at < len(texts):
        text = texts[at]
        at += 1
        if text.startswith("--"):
            name, equals, value = text.partition("=")
            if name in ("--in-place", "--file"):
                return "writer" if name == "--in-place" else "other"
            if name in ("--expression", "--line-length"):
                value = value if equals else (texts[at] if at < len(texts) else "")
                at += 0 if equals else 1
                scripts += [value] if name == "--expression" else []
                explicit = explicit or name == "--expression"
        elif text.startswith("-") and len(text) > 1:
            for position, letter in enumerate(text[1:], start=1):
                if letter in "iI":
                    return "writer"
                if letter == "f":
                    return "other"
                if letter in "el":
                    rest = text[position + 1 :]
                    value = rest or (texts[at] if at < len(texts) else "")
                    at += 0 if rest else 1
                    scripts += [value] if letter == "e" else []
                    explicit = explicit or letter == "e"
                    break
        else:
            files.append(text)
    scripts = scripts if explicit else files[:1]
    return "other" if any(re.search(r"[wWe]", script) for script in scripts) else "reader"


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
        return _sed_kind(texts)
    if name == "find":
        found = set(texts)
        return "runner" if found & set(_FIND_RUNS) else "find-writes" if found & {"-delete", *_FIND_WRITES} else "reader"
    if name == "rg" and any(text.startswith("--pre") for text in texts):
        return "runner"
    if name == "file" and any(text in ("-C", "--compile") for text in texts):
        return "other"
    if name in ("cd", "pushd", "popd", "git", "dd"):
        return "cd" if name == "pushd" else name
    if name in _READERS or name in _ASSIGNERS:
        return "reader" if name in _READERS else "assign"
    if name in _RUNNERS or _INTERPRETER.fullmatch(name):
        return "runner"
    return "copier" if name in _COPIERS else "other"


class _Git(NamedTuple):
    reads: bool
    repos: List[Word]  # named with -C, --git-dir, --work-tree
    sub: str
    args: List[Word]  # the subcommand's


def _git(args: List[Word], risky_env: bool) -> _Git:
    rest, repos, risky = list(args), [], risky_env
    while rest and rest[0].text.startswith("-"):
        option = rest.pop(0)
        name, _, value = option.text.partition("=")
        if name in ("-C", "--git-dir", "--work-tree"):
            repos += [_after(option, len(name) + 1)] if value else rest[:1]
            rest = rest if value else rest[1:]
        elif name in ("-c", "--config-env", "--exec-path", "--namespace"):
            # -c can set an alias, a pager or the hooks path: not a plain read.
            risky = True
            rest = rest if value or name == "--exec-path" else rest[1:]
    sub, sub_args = (rest[0].text, rest[1:]) if rest else ("", [])
    risky = risky or any(word.text.startswith(_GIT_RISKY) for word in sub_args)
    return _Git(not risky and _git_reads(sub, [word.text for word in sub_args]), repos, sub, sub_args)


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


def _messages(words: List[Word], git: Optional[_Git], guarded: List[str]) -> Set[int]:
    """Indices of the words that are a git or gh message (-m, --body, …): text,
    not paths. A message file counts only when it isn't a protected path."""
    name = words[0].text.rsplit("/", 1)[-1] if words else ""
    flags = _MESSAGE_FLAGS.get(name, ()) if name != "git" or (git and git.sub in _GIT_MESSAGES) else ()
    exempt: Set[int] = set()
    for index, word in enumerate(words[1:], start=1):
        for flag in flags:
            if word.text == flag and index + 1 < len(words):
                value, at = words[index + 1].text, index + 1
            elif word.text.startswith(flag + "=") or (len(flag) == 2 and len(word.text) > 2 and word.text.startswith(flag)):
                value, at = word.text[len(flag) :].lstrip("="), index
            else:
                continue
            if flag not in _FILE_FLAGS or not _named(value, guarded):
                exempt.add(at)
    return exempt


def _targets(kind: str, words: List[Word], git: Optional[_Git]) -> List[Word]:
    """What a copier, dd or a changing git command writes; _root follows them,
    relative ones and attached option values included."""
    args = words[1:]
    if kind == "copier":
        explicit = [after for word, after in zip(args, args[1:]) if word.text in ("-t", "--target-directory")]
        options = [word for word in args if word.text.startswith("-")]
        return explicit + options + ([] if explicit else [word for word in args if not word.text.startswith("-")][-1:])
    if kind == "dd":
        return [_after(word, 3) for word in args if word.text.startswith("of=")]
    # git: relative arguments are relative to the repository, which is judged itself.
    return [word for word in git.args if os.path.isabs(word.text) or word.dynamic or word.text.startswith("-")] if git else []


def _root(word: Word, here: Optional[str], guarded: List[str], named: Optional[str]) -> Optional[str]:
    """The guarded path a word names as a file, if any: an option's attached
    value (-o/x, --file=/x) included. A word the shell still expands counts
    when its literal start leads into one, or when the command names one
    anywhere (X=<path>; rm -rf $X)."""
    if word.text.startswith("-"):
        option = _OPTION_VALUE.match(word.text)
        word = _after(word, option.end() if option else 1 if word.text.startswith("--") else 2)
        if not word.text or word.text.startswith("-"):
            return None
    if word.dynamic:
        return _root_of_prefix(word.prefix, here, guarded) or named
    text = word.text
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
    """For each part, the text of the whole pipeline it is in: what a command
    reads on stdin comes from the parts before it."""
    groups: List[List[int]] = [[]]
    for index, (_, _, separator) in enumerate(segments):
        groups[-1].append(index)
        if separator != "|":
            groups.append([])
    text = {index: "\n".join(segments[i][0] + segments[i][1] for i in group) for group in groups for index in group}
    return [text[index] for index in range(len(segments))]


def _command_reason(command: str, cwd: Optional[str], protected: List[str], settings: List[str]) -> Optional[str]:
    """Refuse a command that may write to a protected path or the agent
    settings. Readers (ls, cat, grep, git log, …) may name one; a redirection,
    a copier's destination or a variable may not point at one; any other
    command may not name one in any word but a git or gh message, nor on its
    stdin; runners, substitutions and parts that can't be parsed may not name
    one at all. Relative paths are followed through cd, and anything but a read
    run inside a protected path is refused. Text is data: a heredoc saved or
    piped to a reader, a quoted message, an issue body."""
    guarded = protected + settings
    segments = shell.segments(shell.inline_literal_heredocs(command))
    pairs = [(text + body, separator) for text, body, separator in segments]
    pipelines = _pipelines(segments)
    named = next(filter(None, (_named(text, guarded) for text, _, _ in segments)), None)
    if _SHIFTING_ENV.search(command):
        # HOME= or CDPATH= move where ~ and cd lead: then no naming at all.
        shifted = named or _basename_in(command, protected)
        if shifted:
            return _why(shifted, settings)
    here, previous, scopes, key_written, risky_env = cwd, None, [], False, False
    for index, (text, body, _) in enumerate(segments):
        parsed = shell.words(text)
        if parsed is None:
            unclear = _named(text + body, guarded)
            if unclear:
                return _why(unclear, settings)
            continue
        redirects, rest = _split_redirects(parsed[0])
        found = _command(rest)
        words = found.words
        scopes += [here] * found.opened
        kind = "runner" if found.runs else _kind(words)
        assignments = found.assignments + ([word for word in words[1:] if _ASSIGNMENT.match(word.text)] if kind == "assign" else [])
        risky_env = risky_env or any(_RISKY_ENV.match(word.text) for word in assignments)
        if kind in ("cd", "popd"):
            here, previous = (_cd(words, text, here, previous, protected) if kind == "cd" else _UNKNOWN), here
        at = _chdir(found.chdir, here) if found.chdir else here
        git = _git(words[1:], risky_env) if kind == "git" else None
        reads = kind in ("cd", "popd", "reader", "launcher", "none", "assign") or bool(git and git.reads)
        runs = kind == "runner" or parsed[1] or shell.body_substitutes(text, body)
        unclear = _named(pipelines[index] if kind == "runner" else text + body, guarded) if runs else None
        if unclear:
            return _why(unclear, settings)
        # A variable or wrapper option pointing at one: GIT_DIR=…, X=…, env -C …, sudo -D ….
        for word in [_after(word, word.text.index("=") + 1) for word in assignments] + found.options:
            root = _named(word.text, guarded) or _root(word, at, guarded, None)
            if root:
                return _why(root, settings)
        targets = list(redirects)
        if not reads:
            # What it may write: every word but a message (only a copier's
            # options and destination), and its stdin, may not name one.
            exempt = _messages(words, git, guarded)
            written = _targets(kind, words, git)
            checked = written if kind == "copier" else [word for i, word in enumerate(words) if i not in exempt]
            name = words[0].text.rsplit("/", 1)[-1] if words else ""
            stdin_is_data = name in ("tee", "gh") or bool(git and git.sub in _GIT_MESSAGES)
            piped = index > 0 and segments[index - 1][2] == "|"
            stdin = "" if stdin_is_data else body + (pipelines[index] if piped else "")
            mentioned = next(filter(None, (_named(word.text, guarded) for word in checked)), None) or _named(stdin, guarded)
            if mentioned:
                return _why(mentioned, settings)
            paths = written if kind in ("copier", "dd", "git") else [w for w in checked if not any(c.isspace() for c in w.text)]
            # No -C: the repository it is in, which may be anywhere after a cd it can't follow.
            current = [] if at is None else [Word("", dynamic=True)] if at == _UNKNOWN else [Word(at)]
            targets += paths + ((git.repos or current) if git else [])
        if words and "/" in words[0].text and kind != "launcher":
            targets.append(words[0])
        for word in targets:
            root = _root(word, at, guarded, named)
            if root:
                return _why(root, settings)
        inside = None if reads or at in (None, _UNKNOWN) else _inside(at, protected)
        if inside:
            return f"it runs inside {inside}"
        tee = bool(words) and words[0].text == "tee"
        written = [word.text for word in redirects + ([word for word in words[1:] if not word.text.startswith("-")] if tee else [])]
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
        for _ in range(min(found.closed, len(scopes))):
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
