---
name: blindfold
description: "ALWAYS ACTIVE, no need to load. Be cautious yourself first: work blind by default, avoid reading or printing secrets, env files or credentials unless the task needs it; blindfold's masking is only the last-resort failsafe. <blindfold kind=K len=N id=H> = a hidden value (kind: env:NAME known secret, or a rule like stripe-key/jwt/high-entropy; len; id: same value, same id). Work by name, presence, length, id. Never recover a value (re-read, cat/head/xxd/base64, split/encode, subagent, guess), never write a placeholder into a file, never bypass or disable blindfold. Need a value: ask the user. False positive: propose allow_ids/disabled_rules in ~/.config/blindfold/config.json, which only the user can change (blindfold refuses agent edits to its own files, config and hooks), so give them the exact command; never propose allowing env:*. A real secret visible anywhere: lead with ⚠️ SECRET EXPOSED, name it, never repeat it, say rotate it. Load for examples."
---

# blindfold: secrets are masked, and that is intended

**You are the first line of defence; blindfold is the safety net.** Be cautious with
anything that is or might be sensitive: credentials, keys, tokens, passwords,
connection strings, personal data. Work blind by default. Don't read secret
files, dump environment variables or print config unless the task really needs
it, and even then prefer commands that report names, presence or lengths. The
masking below catches what slips through; it is not permission to be careless,
and it can miss things (a short password with no telling name next to it).

A hook masks secrets in every tool result before you see it: file reads, command
output, search results, MCP responses. You will never see a secret's value, and
you don't need to. Treat the masking as a feature of the environment, not an
obstacle.

## What a masked value looks like

```
<blindfold kind=env:STRIPE_API_KEY len=107 id=3f9a1c>
```

- `kind`: why it was masked.
  - `env:NAME`: the exact value of a known secret, so you know which one it is.
  - A rule name such as `stripe-key`, `private-key`, `jwt`, `url-password`,
    `auth-header`, `env-assignment`, `named-secret` or `cli-secret-flag`: it
    matched a secret's shape or a secret-looking name.
  - `high-entropy`: a long random-looking token.
- `len`: the value's length. Use it to confirm a value is set, or plausibly the
  right kind ("set, 107 chars").
- `id`: a keyed fingerprint. The same value always gets the same id on this
  machine, so you can tell whether two places hold the same secret, or whether
  it changed between two reads. The id can't be reversed or checked against a
  guess.

A tool result that had something masked ends with a blindfold note listing what was
hidden. A result reading `<blindfold: output withheld …>` means the masker failed
and withheld everything. Re-run, or ask the user.

## Working blind

- **Report on secrets by name, presence, length and id.** Never by value:
  "STRIPE_API_KEY is set (107 chars, id 3f9a1c) on staging and production; the
  ids match, so both use the same key."
- **Let tools hold the secret.** Run the program or CLI that loads it itself
  (`op run`, a project CLI, `heroku run`). Don't copy a value into a command.
- **Compare without seeing.** To check two copies match, compare their ids, or
  have a command compare them and print only `match` or `differ`.
- **To set or rotate a secret**, give the user the command to run with the value
  read from a secure prompt or a password manager. Don't put a value in it
  yourself.
- **Keep placeholders out of files.** If you edit a file containing a
  placeholder, leave that line alone. Writing a placeholder would replace the
  real secret with blindfold's text, and the write is refused anyway.

## Never work around the masking

These all defeat the purpose and count as leaking, even when the intent is
innocent:

- Re-reading the value another way: `cat`, `head -c`, `xxd`, `od`, `strings`,
  `sed -n`, piping through `base64`, `rev`, `tr`, `cut`, or printing it a few
  characters at a time.
- Encoding, splitting, hashing or transforming a value so it slips past the mask
  (base64, hex, URL encoding, character arrays, string concatenation).
- Asking a subagent, a script or another tool to read and repeat it.
- Guessing or reconstructing a value from its length, id, prefix or context.
- Turning blindfold off, editing its config or bypassing its hooks. Only the user
  decides that.

If a task truly needs a value you can't see, stop and ask the user. Explain what
you need and why. Usually they can run one command themselves.

## False positives: overriding, with explicit confirmation only

Sometimes blindfold masks something that isn't secret: a public client id, a content
hash, a random-looking test fixture. If the task needs that value:

1. Tell the user what was masked and why you think it's a false positive:
   "`kind=high-entropy len=40 id=9b2e71` in package-lock.json looks like an
   integrity hash, not a secret."
2. Propose the narrowest override:
   - one value, by its id: add `"9b2e71"` to `allow_ids`
   - or, for a rule that's wrong in this setup, add its kind to `disabled_rules`
3. Give the user the exact command that makes the change, for them to run
   (they can type `! <command>`). You can't change `~/.config/blindfold/config.json`
   yourself: blindfold refuses agent changes to its own code, config, key, skill
   and hook settings, so an accident can't switch masking off.
4. Never allow a `env:*` kind (a known secret), never disable masking wholesale,
   and never remove blindfold's hooks, even with permission to "make it work". Point
   the user to the README instead.

## If a secret leaks

A secret has leaked if its real value appears anywhere you can see it: a tool
result blindfold didn't catch, a message from the user, your own output. When that
happens:

1. **Stop and tell the user loudly, at the top of your reply:** "⚠️ SECRET
   EXPOSED: <name or kind>, seen in <where>. It has reached the model provider
   and should be rotated."
2. Don't repeat the value, not even partially, and don't use it.
3. Name what to rotate and where it's used, so the user can plan the rotation.
4. If the user asks, suggest the rule or `known_secret_files` entry that would
   have caught it, so blindfold masks it next time.

blindfold also warns on its own when a known secret's value appears in a prompt, a
tool call or your reply. Treat any such warning as a leak.
