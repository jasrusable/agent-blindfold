# blindfold

**Keep secrets out of your AI coding agent's context.**

Coding agents read `.env` files, print config and tail logs. Every secret in
that output is sent to the model provider and saved in transcripts. blindfold
is a hook for [Claude Code](https://claude.com/claude-code) and
[Grok](https://x.ai) that masks secrets in tool output before the model sees
them, so the agent can keep working without ever holding a value:

```diff
- STRIPE_API_KEY=sk_live_51H…
+ STRIPE_API_KEY=<blindfold kind=env:STRIPE_API_KEY len=107 id=3f9a1c>
```

The placeholder still says what was there (`kind`), how long it was (`len`)
and a per-machine fingerprint (`id`). So "is it set?" and "do these two match?"
can still be answered without seeing the value.

## Install

Python 3.9+, no dependencies.

```sh
git clone https://github.com/jasrusable/agent-blindfold ~/.local/share/agent-blindfold
~/.local/share/agent-blindfold/bin/blindfold install          # dry run: shows the change
~/.local/share/agent-blindfold/bin/blindfold install --apply  # adds the hooks and the skill
~/.local/share/agent-blindfold/bin/blindfold selftest --installed --agent claude --agent grok
```

One install covers both agents (Grok reads Claude Code's hooks). Install from a
clone you don't edit: the hook runs on every tool call in every session, so
develop in another checkout and `git pull` the installed one when ready. (You
run the pull: agents can't change the installed copy.)

## What it catches

1. **Your actual secrets, by exact value.** blindfold reads your real `.env`
   files and environment, then masks those values anywhere they appear: raw,
   base64, URL-encoded or JSON-escaped. Multi-line keys are matched line by line.
2. **Known formats.** Stripe, GitHub, AWS, Slack, OpenAI, Anthropic, Google,
   Sentry, private keys, JWTs, auth headers, passwords in URLs, `--token …`,
   `PASSWORD=…`.
3. **Random-looking tokens** that nothing else named.

It also:

- refuses commands that print a bare secret (1Password reads, Keychain password reads)
- blocks prompts where you paste a secret by mistake
- warns you to rotate anything that got through anyway

## Safe by default

- **Fails closed.** If masking crashes or runs out of time, the output is
  withheld, not passed through.
- **Can't lock you out.** If the pre-call check breaks, calls still go through,
  with a warning.
- **Guards itself.** Agents can't edit the installed copy, its config or key,
  or its hook entries in the agent settings, and can't turn hooks off. They
  hand you the exact command instead, so an accident can't disable masking.
- **Prefers false positives.** Over-masking costs a little friction; a leak
  costs a rotation.
- **Works with your agent.** A skill and a session note tell the agent to
  work blind and never try to recover a masked value. They also tell it to
  flag any exposure loudly.

blindfold guards against **accidents**, not an agent set on defeating it. For
that, keep secrets off disk (for example `op run` with `op://` references).

## Commands

| Command | Does |
|---------|------|
| `blindfold doctor` | Shows config, the secret files found and install state. Never prints values. |
| `blindfold scan [file]` | Masks a file or stdin. |
| `blindfold selftest` | Canary tests, optionally through a real agent. `--installed` tests the hooks your agents actually run; without it, this checkout's. |

## Configuration

Optional, in `~/.config/blindfold/config.json`:

```json
{
  "extra_known_secret_files": ["~/work/*/.env"],
  "allow_ids": ["9b2e71"],
  "disabled_rules": []
}
```

To allow a false positive, add the `id` from its placeholder to `allow_ids`.
Your own secrets (`env:*`) can't be allowed. All options, how it works and the
known gaps are in [docs/design.md](docs/design.md).

## Development

```sh
python3 -m unittest discover -s tests -t .
```

See [AGENTS.md](AGENTS.md) for the layout and invariants. Test secrets are
assembled at runtime, so the repo doesn't trip secret scanners.

## Licence

MIT
