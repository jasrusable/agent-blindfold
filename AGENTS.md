# blindfold: notes for agents working on this repo

blindfold masks secrets in AI agents' tool output. It is security code that must
**fail closed**: when in doubt, mask; when masking fails, withhold.

- **Layout:**
  - `blindfold/rules.py`: patterns and name and value judgement. Data plus small pure functions.
  - `blindfold/known.py`: known secret values from files and env.
  - `blindfold/mask.py`: the engine.
  - `blindfold/structure.py`: shape-preserving JSON walk.
  - `blindfold/events.py`: one view of Claude and Grok events.
  - `blindfold/handlers.py`: one pure function per hook event.
  - `blindfold/runtime.py`: config and masker, with the safe fallback.
  - `blindfold/hook.py`: process I/O, never raises.
- **Invariants (each one has tests):**
  - A PostToolUse reply keeps the tool's exact structure and types; Claude ignores anything else.
  - Nothing in `hook.py` may raise.
  - The walk and the known-value regex build are iterative (no deep recursion).
  - Masking runs under a hard deadline (a killed child process), not just SIGALRM.
  - Placeholders follow `PLACEHOLDER_RE`.
  - Masking is idempotent.
  - Text that only looks like a placeholder gets no protection.
- **Tests first:**
  - Every false positive or negative found in the wild becomes a corpus case in `tests/corpus.py`.
  - Build fake secrets from fragments (`j("sk", "_live_", …)`), never as literals.
  - Run `python3 -m unittest discover -s tests -t .` (also under Python 3.9).
  - After touching hook I/O, run `bin/blindfold selftest --agent claude --agent grok`.
- **Calibrate on real code:** `scripts/fp_eval.py <repos>` prints only masked lines.
- **Never point the installed hook at a working copy:** it runs on every tool call of every session on the machine. Develop here, test, then `git -C ~/.local/share/agent-blindfold pull`.
- **Fail safe before a call, closed after it:** a PreToolUse/UserPromptSubmit failure lets the call or prompt through with a warning (still refusing commands that name the 1Password or Keychain CLI); a PostToolUse failure withholds the output.
- **Docs:** `README.md` stays short; details go in `docs/design.md`. The guard refuses an agent writing a literal placeholder, so tests assemble them at runtime and doc examples are inserted by a script.
- **Keep it simple:** Python stdlib only, no dependencies. Prefer data plus one generic path over special cases.
