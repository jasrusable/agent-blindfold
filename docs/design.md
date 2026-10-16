# blindfold: design notes

The details behind the [README](../README.md).

## Hooks and detection

blindfold is a set of hooks the agent runs at fixed points:

| Hook | What blindfold does |
|------|----------------|
| `PostToolUse` | Masks every string in the tool result and sends back **the same structure**. |
| `PreToolUse` | Refuses a call that would write a placeholder (it would overwrite the real secret) or that carries a known secret's value. In Claude Code it also wraps Bash commands so a failing one can still be masked (see below). |
| `UserPromptSubmit` | Blocks a prompt containing a known secret's value, or a pasted vendor-format secret (`ghp_…`, `sk_live_…`, a private key), before it reaches the model. |
| `Stop` | Warns you to rotate a known secret whose value reached the model anyway. |
| `SessionStart` | Tells the agent what placeholders mean and how to work blind. |

Detection has three layers:

1. **Exact match of known values.** This one is deterministic. blindfold reads your
   real secret files (`.env`, `.env.local`, `.env.production` and so on;
   templates like `.env.sample` are deliberately excluded) and the process
   environment on every call. Any of those values is masked wherever it
   appears, and so are its base64, URL-encoded and JSON-escaped forms, its
   Unicode NFC/NFD forms, and either case of a hex value.
2. **Rules.** Vendor formats (Stripe, GitHub, AWS, Slack, Anthropic, OpenAI,
   Google, Sentry, PEM private keys, JWTs, and more) plus context: `NAME=value`
   lines, `"password": "…"`, `--token …`, auth headers, credentials in URLs.
   Names are judged segment by segment, so `STRIPE_SECRET_KEY` counts but
   `max_tokens` and `TOKEN_URL` don't.
3. **Entropy.** Long random-looking tokens no rule named.

It **fails closed** after a call: if masking fails, or runs past its deadline
in a child process that is then killed, the output is withheld rather than
passed through. It fails *safe* before a call: if that check breaks, the call
or prompt goes through with a warning (commands naming the 1Password or
Keychain CLI are still refused), so a bug can't lock anyone out. If blindfold
can't even load, the launcher's stdlib fallback withholds tool output. When in doubt it
masks; a false positive costs a little friction, a false negative costs a
rotation.

### Failing commands in Claude Code

Claude Code won't let a hook replace the output of a tool call that failed.
That would leave `cat .env; exit 1` or a crashing script that dumps its config
unmasked. So blindfold rewrites each Bash command to exit 0 and report the real exit
code on stderr as `[blindfold: exit code N; …]`, which sends its output down the
success path that blindfold can mask.
- A plain command runs in a `{ … }` group, so `cd` still carries over to the next call.
- A command that could end the shell itself (`exit`, `exec`, `set -e`) runs in a
  subshell, and `set -e` keeps working.
- The status is never tested with `||`, which would silently disable `set -e`.
- Your permission rules still match the rewritten command; the selftest checks
  this.

Grok doesn't need any of this, since it masks failed calls like any other.

### Why the same structure

Claude Code silently ignores a replacement that isn't the tool's own output
shape. A plain string is ignored too, and the original reaches the model with
no error. Grok accepts its own result edited in place. Editing every string in
place is the one form both honour. blindfold's selftest checks this against the real
agents, because it's exactly what an agent upgrade could break.

### Guarding itself

Before each call, blindfold refuses one that would change blindfold itself:

- **File writes and edits** into the installed copy it runs from, `~/.config/blindfold`
  (config and key), or the skill links.
- **Settings edits** that touch blindfold's entries in `~/.claude/settings.json` or
  `settings.local.json`, or a full write that drops them. Other settings edits
  are fine.
- **Turning hooks off:** `disableAllHooks` written into a settings file, by any tool.
- **Shell commands that use a protected path:** writing into it, running
  inside it (`cd` included), feeding its files to `xargs`, a shell or a loop,
  or running code (Python, Node, …) that names it. Read-only parts (`ls`,
  `cat`, `grep`, `git log`, `blindfold doctor`, …) are fine, and so is text that
  only mentions a path: a note or doc written with `cat`, `tee`, `echo` or
  `printf` to a file elsewhere. Shell rewrites of the agent settings file are
  refused; the file-edit tools are checked precisely instead.

Commands are split the way the shell splits them (quotes, escapes,
here-documents), so a `|` inside a grep pattern or a path inside a heredoc of
notes isn't mistaken for use. The same applies to the blocked commands: a
heredoc saved to a file is data, while one piped into a shell is judged.

Changes to blindfold go through the user, who can type `! <command>`. Your
development checkout is not protected; only the copy the hook runs from is.
Like the command denylist, this stops accidents, not an agent set on getting
round it (a path it builds at runtime isn't seen).

### Placeholders in docs

The placeholder guard refuses writing a placeholder into a file, since it
would replace the real value. Markdown docs (`.md`, `.mdx`, `.rst`) are the
exception: there a placeholder is an example.

## Configuration reference

`~/.config/blindfold/config.json`, all optional:

```json
{
  "extra_known_secret_files": ["~/work/*/.env"],
  "use_default_known_secret_files": true,
  "min_known_length": 8,
  "entropy": true,
  "min_entropy": 4.2,
  "allow": [],
  "allow_ids": ["9b2e71"],
  "disabled_rules": [],
  "guard_placeholders": true,
  "guard_known_values": true,
  "wrap_claude_bash": true,
  "blocked_commands": ["\\bop\\s+read\\b"]
}
```

- **Known secret files:** `extra_known_secret_files` adds to the defaults. These
  are your real secret files under `~`, `~/projects/*` and `~/.config/*`, never
  committed templates. To opt out of the defaults, set
  `"use_default_known_secret_files": false`.
- **Blocked commands:** some commands print a secret with nothing around it that
  marks it as one: macOS Keychain reads that print the password (`-w`/`-g`), a
  Keychain dump, `op read`, `op item get --reveal`. Masking can't catch those,
  so they're refused by default. `op run` and other tools that consume a secret
  themselves are fine.
- **Weak values** like `DB_PASSWORD=postgres` aren't treated as known secrets,
  since they'd match ordinary text everywhere. They are still masked where
  they're assigned to a secret name.

- **False positives:** add the placeholder's `id` to `allow_ids`. That shows
  that one value from then on, and nobody has to type it. Known secrets
  (`env:*`) can't be allowed this way.
- **Noisy rules:** add a rule's kind to `disabled_rules`.
- **Broken config:** a config that doesn't parse, or has a wrongly typed value,
  falls back to the defaults, which only ever mask more, and blindfold warns on every
  call until it's fixed.
- **Environment overrides:** `BLINDFOLD_CONFIG` and `BLINDFOLD_HOME` point blindfold at a
  different config. Anything that can set the agent's environment (including a
  project's `.claude/settings.json` `env`) can change them. That's outside the
  accidental-exposure threat model, but worth knowing.

## Threat model and known gaps

blindfold prevents **accidental** exposure. It does not stop an agent that sets out
to defeat it: one that encodes a value before printing it can get past pattern
matching. For that, keep secrets off disk entirely, for example with 1Password
`op run` and `op://` references.

Not covered:

- **Channels that don't run hooks:** files you `@mention`, an agent's "file
  changed on disk" reminders, background task notifications, and
  OpenTelemetry/analytics, which record output before hooks run.
- **What Claude Code won't let blindfold mask:** the output of failed non-Bash calls
  (an MCP error, a failed `Read`), commands Claude kills (its timeout, or Esc),
  and `kill $$`. When such output holds a secret, blindfold tells you immediately
  which kinds of secret went through so you can rotate them, and its
  end-of-turn transcript check catches known values too.
- **Interplay with other hooks in Claude Code:** another `PreToolUse` hook that
  rewrites Bash input can drop blindfold's wrapper; whichever writes last wins. Your
  own `PostToolUseFailure` hooks stop seeing Bash failures, because wrapped
  commands report success. Deny and allow rules still apply to wrapped commands
  (the selftest checks both). When you approve a wrapped command and choose
  "don't ask again", check the rule Claude saves.
- **Grok's transcript and scrollback** keep the original output by design. The
  model doesn't see it, but the file on disk has it. Claude Code stores the
  masked version.
- **Unrecognisable secrets:** a short password with no telling name next to it
  isn't caught by rules. List its file so exact matching covers it.
- **Split secrets:** values split across separate outputs (stdout vs stderr) or
  broken across wrapped lines.
- **Images and PDFs:** their readable text (raw, deflated PDF streams, PNG text
  chunks) is scanned, and a hit masks the whole file. Text drawn as pixels, like
  a screenshot of a secret, can't be read.

## Acknowledgements

Vendor patterns follow [gitleaks](https://github.com/gitleaks/gitleaks) (MIT).
Ideas were also drawn from
[redact-hook](https://github.com/SilentAutomaton/redact-hook) (MIT),
[claude-code-redaction-hooks](https://github.com/l-mb/claude-code-redaction-hooks)
(Apache-2.0), [maisecrets](https://github.com/Mcpgate-de/maisecrets) (Apache-2.0)
and cadence-hooks: segment-based name matching and the canary transcript check.
