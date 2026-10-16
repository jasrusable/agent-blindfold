"""Randomised invariants. Seeded for reproducibility; BLINDFOLD_FUZZ_ITERATIONS runs more."""

import io
import json
import os
import random
import sys
import unittest
from unittest import mock

from blindfold import hook
from blindfold.structure import deep_map
from blindfold.config import Config
from blindfold.known import KnownSecret
from blindfold.mask import Masker

from . import corpus
from .helpers import reply as hook_reply

ITERATIONS = int(os.environ.get("BLINDFOLD_FUZZ_ITERATIONS", "400"))
KNOWN = [corpus.rand(n) for n in (12, 20, 33, 48)] + ["p@ss w0rd/with:sym!" + corpus.rand(6), corpus.hexs(64)]
PATTERN_SECRETS = [corpus.STRIPE_LIVE, corpus.GITHUB_PAT, corpus.ANTHROPIC, corpus.JWT, corpus.NPM, corpus.SLACK_BOT]
MASKER = Masker(known=[KnownSecret(v, f"K{i}_SECRET") for i, v in enumerate(KNOWN)], key=b"f" * 32)
CFG = Config(use_default_known_secret_files=False)
NOISE = ["", " ", "\n", "\t", "é", "日本", "🙂", '"', "'", "`", "=", ":", "/", "\\", "\x1b[31m", "\x1b[0m", "{", "}", ",", "x", "Z9"]


def noisy(rng: random.Random, secret: str) -> str:
    """The secret with random surroundings, sometimes split by an ANSI escape."""
    if rng.random() < 0.2 and len(secret) > 4:
        cut = rng.randrange(1, len(secret) - 1)
        secret = secret[:cut] + "\x1b[0m" + secret[cut:]
    return "".join(rng.choice(NOISE) for _ in range(rng.randrange(4))) + secret + "".join(rng.choice(NOISE) for _ in range(rng.randrange(4)))


def random_leaf(rng: random.Random, planted: list):
    roll = rng.random()
    if roll < 0.25:
        secret = rng.choice(KNOWN)
        planted.append(secret)
        return noisy(rng, secret)
    if roll < 0.35:
        return rng.choice(["", "ok", "plain text\nline 2", "x" * rng.randrange(1, 3000), "".join(rng.choice(NOISE) for _ in range(20))])
    if roll < 0.45:
        secret = rng.choice(PATTERN_SECRETS)
        return f"token: {secret}"
    return rng.choice([0, 1, -5, 3.14, True, False, None, "hello world"])


def random_tree(rng: random.Random, depth: int, planted: list):
    if depth <= 0 or rng.random() < 0.3:
        return random_leaf(rng, planted)
    if rng.random() < 0.5:
        return [random_tree(rng, depth - 1, planted) for _ in range(rng.randrange(4))]
    return {f"k{i}": random_tree(rng, depth - 1, planted) for i in range(rng.randrange(4))}


def flatten(value) -> str:
    parts = []
    deep_map(value, lambda s: parts.append(s) or s)
    return "\x00".join(parts)


def same_shape(a, b) -> bool:
    if isinstance(a, dict):
        return isinstance(b, dict) and list(a) == list(b) and all(same_shape(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(same_shape(x, y) for x, y in zip(a, b))
    if isinstance(a, str):
        return isinstance(b, str)
    return a == b and type(a) is type(b)


class Invariants(unittest.TestCase):
    def test_random_tool_results(self):
        rng = random.Random(1016)
        for i in range(ITERATIONS):
            planted: list = []
            tree = random_tree(rng, 4, planted)
            event = {"hook_event_name": "PostToolUse", "tool_name": "mcp__fuzz", "tool_response": tree}
            with self.subTest(iteration=i):
                reply = hook_reply(event, MASKER)
                out = reply["hookSpecificOutput"]["updatedToolOutput"] if reply else tree
                self.assertTrue(same_shape(tree, out), "structure and non-string values must survive")
                text = flatten(out)
                for secret in KNOWN:
                    self.assertNotIn(secret, text)
                if reply:
                    again = hook_reply({**event, "tool_response": out}, MASKER)
                    self.assertIsNone(again, "masking must be idempotent")

    def test_random_bytes_never_crash_or_echo(self):
        rng = random.Random(7)
        for i in range(ITERATIONS // 4):
            secret = rng.choice(KNOWN)
            raw = bytes(rng.randrange(256) for _ in range(rng.randrange(200))) + secret.encode()
            stdin = io.TextIOWrapper(io.BytesIO(raw))
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(iteration=i), mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
                code = hook.main()
                self.assertIn(code, (0, 2))
                self.assertNotIn(secret, stdout.getvalue())

    def test_random_valid_events_of_every_kind(self):
        rng = random.Random(99)
        names = ["PostToolUse", "PreToolUse", "UserPromptSubmit", "Stop", "SessionStart", "PostToolUseFailure", "Notification", ""]
        for i in range(ITERATIONS // 2):
            planted: list = []
            event = {
                "hook_event_name": rng.choice(names),
                "tool_name": rng.choice(["Bash", "Write", "Edit", "Read", "mcp__x"]),
                "tool_input": random_tree(rng, 2, planted),
                "tool_response": random_tree(rng, 3, planted),
                "prompt": random_leaf(rng, planted),
                "last_assistant_message": random_leaf(rng, planted),
            }
            with self.subTest(iteration=i):
                reply = hook_reply(event, MASKER)
                rendered = json.dumps(reply)
                for secret in KNOWN:
                    if event["hook_event_name"] != "PostToolUse":
                        self.assertNotIn(secret, rendered, "replies other than a masked result never carry values")


if __name__ == "__main__":
    unittest.main()
