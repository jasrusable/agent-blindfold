import re
import time
import unittest

from blindfold.known import KnownSecret, encoded_variants, parse_env_text
from blindfold.mask import PLACEHOLDER_RE, Masker
from blindfold.rules import is_secret_name

from . import corpus

KEY = b"k" * 32


def masker(**kwargs) -> Masker:
    return Masker(key=KEY, **kwargs)


class MustMask(unittest.TestCase):
    def test_every_corpus_secret_disappears(self):
        m = masker()
        for text, secret in corpus.MUST_MASK:
            with self.subTest(text=text[:60]):
                masked, findings = m.mask(text)
                self.assertTrue(findings, f"nothing masked in: {text[:80]!r}")
                if secret:
                    self.assertNotIn(secret, masked)
                self.assertRegex(masked, PLACEHOLDER_RE)

    def test_no_secret_fragment_of_eight_chars_survives(self):
        m = masker()
        for text, secret in corpus.MUST_MASK:
            if not secret or len(secret) < 16:
                continue
            masked, _ = m.mask(text)
            with self.subTest(secret=secret[:12]):
                chunks = {secret[i : i + 8] for i in range(0, len(secret) - 8, 4)}
                leaked = [c for c in chunks if c in masked and re.search(r"[0-9]", c) and re.search(r"[A-Za-z]", c)]
                self.assertEqual(leaked, [], f"fragments of the secret survived in {masked[:120]!r}")


class MustNotMask(unittest.TestCase):
    def test_ordinary_output_is_untouched(self):
        m = masker()
        for text in corpus.MUST_NOT_MASK:
            with self.subTest(text=text[:60]):
                masked, findings = m.mask(text)
                self.assertEqual(findings, [], f"false positive {[f.kind for f in findings]} in {text[:80]!r}")
                self.assertEqual(masked, text)

    def test_unchanged_text_is_returned_as_is_even_with_ansi(self):
        m = masker()
        text = "\x1b[32mall good\x1b[0m"
        self.assertEqual(m.mask(text), (text, []))


class Names(unittest.TestCase):
    def test_secret_names(self):
        for name in ["PASSWORD", "db_password", "STRIPE_SECRET_KEY", "apiKey", "api_key", "API-KEY", "clientSecret",
                     "GITHUB_TOKEN", "accessToken", "refresh_token", "SENTRY_DSN", "PRIVATE_KEY", "signingKey",
                     "WEBHOOK_SECRET", "OP_SERVICE_ACCOUNT_TOKEN", "LICENSE_KEY", "session_cookie"]:
            with self.subTest(name=name):
                self.assertTrue(is_secret_name(name))

    def test_not_secret_names(self):
        for name in ["max_tokens", "KEY_ID", "API_KEY_ID", "TOKEN_URL", "tokenizer_path", "token_type",
                     "NEXT_PUBLIC_STRIPE_KEY", "STRIPE_PUBLISHABLE_KEY", "password_length", "PASSWORD_MIN",
                     "key", "primary_key", "cache_key", "SECRET_ROTATION_DAYS", "secretsManager", "num_tokens"]:
            with self.subTest(name=name):
                self.assertFalse(is_secret_name(name))


class Placeholders(unittest.TestCase):
    def test_shape_and_determinism(self):
        m = masker()
        a, _ = m.mask(f"STRIPE_API_KEY={corpus.STRIPE_LIVE}")
        b, _ = m.mask(f"other={corpus.STRIPE_LIVE}")
        ids = re.findall(r"id=([0-9a-f]{6})", a + b)
        self.assertEqual(len(set(ids)), 1, "the same value must get the same id")
        self.assertIn(f"len={len(corpus.STRIPE_LIVE)}", a)

    def test_ids_are_keyed(self):
        text = f"STRIPE_API_KEY={corpus.STRIPE_LIVE}"
        one = Masker(key=b"a" * 32).mask(text)[0]
        two = Masker(key=b"b" * 32).mask(text)[0]
        self.assertNotEqual(one, two)

    def test_idempotent(self):
        m = masker()
        for text, _ in corpus.MUST_MASK:
            once, _ = m.mask(text)
            twice, findings = m.mask(once)
            with self.subTest(text=text[:40]):
                self.assertEqual(once, twice)
                self.assertEqual(findings, [])

    def test_kind_is_sanitised(self):
        m = masker(known=[KnownSecret("A1b2C3d4E5f6G7h8", "weird name>with<chars")])
        masked, _ = m.mask("x A1b2C3d4E5f6G7h8 y")
        self.assertRegex(masked, PLACEHOLDER_RE)


class KnownValues(unittest.TestCase):
    def test_exact_match_wins_and_names_the_secret(self):
        secret = corpus.rand(40)
        m = masker(known=[KnownSecret(secret, "PAYMENT_WEBHOOK_SECRET")])
        masked, findings = m.mask(f"webhook?token={secret}&x=1 and again {secret}")
        self.assertNotIn(secret, masked)
        self.assertEqual({f.kind for f in findings}, {"env:PAYMENT_WEBHOOK_SECRET"})

    def test_hex_and_uuid_known_secrets_are_masked(self):
        hex_secret = corpus.hexs(64)
        uuid_secret = "0f8e1d2c-3b4a-4f5e-8d7c-6b5a49382716"
        m = masker(known=[KnownSecret(hex_secret, "A"), KnownSecret(uuid_secret, "HEROKU_API_KEY")])
        masked, _ = m.mask(f"{hex_secret} {uuid_secret}")
        self.assertNotIn(hex_secret, masked)
        self.assertNotIn(uuid_secret, masked)

    def test_encoded_variants_are_masked(self):
        secret = "p@ss/word+" + corpus.rand(12)
        m = masker(known=[KnownSecret(secret, "DB_PASSWORD")])
        for encoded, _suffix in encoded_variants(secret):
            with self.subTest(encoded=_suffix or "raw"):
                masked, findings = m.mask(f"value: {encoded} end")
                self.assertNotIn(encoded, masked)
                self.assertTrue(findings)

    def test_longest_known_value_wins(self):
        short, long = "Abc123xyz789", "Abc123xyz789-plus-more-QQ"
        m = masker(known=[KnownSecret(short, "A_TOKEN"), KnownSecret(long, "B_TOKEN")])
        masked, findings = m.mask(long)
        self.assertEqual([f.kind for f in findings], ["env:B_TOKEN"])
        self.assertNotIn("plus-more", masked)

    def test_env_parser(self):
        text = "\n".join([
            "# comment",
            "export API_KEY='" + "Q" * 3 + corpus.rand(20) + "'",
            "ENVIRONMENT=development",
            "PORT=8000",
            "WEBAPP_BASE_URL=https://app.example.com",
            "DATABASE_URL=" + corpus.DB_URL,
            "RANDOM_THING=" + corpus.rand(32),
            "PASSWORD=changeme",
            "SHORT_SECRET=abc",
            'QUOTED_TOKEN="' + corpus.rand(16) + '"  # trailing comment',
        ])
        names = sorted({s.name for s in parse_env_text(text, 8)})
        self.assertEqual(names, ["API_KEY", "DATABASE_URL", "QUOTED_TOKEN", "RANDOM_THING"])
        values = {s.value for s in parse_env_text(text, 8)}
        self.assertIn(corpus.DB_PASSWORD, values, "the password inside a URL is its own known value")
        self.assertNotIn("development", values)


class Overrides(unittest.TestCase):
    def test_allow_ids_unmasks_one_rule_hit(self):
        text = f"some log line {corpus.GENERIC_TOKEN} more"
        masked, findings = masker().mask(text)
        allowed = masker(allow_ids=[findings[0].fingerprint])
        self.assertEqual(allowed.mask(text), (text, []))

    def test_allow_ids_never_unmasks_a_known_secret(self):
        secret = corpus.rand(30)
        base = masker(known=[KnownSecret(secret, "API_TOKEN")])
        _, findings = base.mask(secret)
        allowed = masker(known=[KnownSecret(secret, "API_TOKEN")], allow_ids=[findings[0].fingerprint])
        masked, _ = allowed.mask(secret)
        self.assertNotIn(secret, masked)

    def test_disabled_rules(self):
        text = f"some log line {corpus.GENERIC_TOKEN} more"
        self.assertEqual(masker(disabled_rules=["high-entropy"]).mask(text), (text, []))


class Performance(unittest.TestCase):
    def test_large_and_pathological_inputs_are_fast(self):
        known = [KnownSecret(corpus.rand(40), f"K{i}_TOKEN") for i in range(300)]
        m = masker(known=known)
        cases = {
            "1MB log": ("INFO request ok path=/api/v1/items status=200 took=12ms\n" * 18000),
            "minified": ("a" * 50 + "=" + "b" * 50 + ";") * 10000,
            "one long word": "x" * 1_000_000,
            "many assignments": "token_count: 5\n" * 50000,
            "dense equals": "=" * 500_000,
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                started = time.monotonic()
                m.mask(text)
                self.assertLess(time.monotonic() - started, 3.0, f"{name} too slow")


if __name__ == "__main__":
    unittest.main()
