"""Test corpus. Every secret-shaped value is assembled from fragments at runtime,
so no file in this repo trips secret scanners (or push protection) on a fake key.
"""

import random
import string

_rng = random.Random(20261016)
ALNUM = string.ascii_letters + string.digits


def rand(n: int, alphabet: str = ALNUM) -> str:
    # Guarantee mixed classes so entropy-based checks see a realistic token.
    while True:
        value = "".join(_rng.choice(alphabet) for _ in range(n))
        if alphabet != ALNUM or (any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value)):
            return value


def hexs(n: int) -> str:
    return "".join(_rng.choice("0123456789abcdef") for _ in range(n))


def j(*parts: str) -> str:
    return "".join(parts)


def png_base64(size: int = 400) -> str:
    """Base64 of bytes that start with a real PNG signature."""
    import base64

    return base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(_rng.randrange(256) for _ in range(size))).decode()


STRIPE_LIVE = j("sk", "_live_", rand(99))
STRIPE_RESTRICTED = j("rk", "_live_", rand(99))
STRIPE_WEBHOOK = j("wh", "sec_", rand(32))
GITHUB_PAT = j("gh", "p_", rand(36))
GITHUB_FINE = j("github", "_pat_", rand(82, ALNUM + "_"))
AWS_KEY_ID = j("AK", "IA", rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))
SLACK_BOT = j("xo", "xb-", "1234567890", "-", "0987654321", "-", rand(24))
ANTHROPIC = j("sk-", "ant-", "api03-", rand(80, ALNUM + "-_"), "AA")
OPENAI = j("sk-", "proj-", rand(20), "T3Blbk", "FJ", rand(20))
GOOGLE = j("AI", "za", rand(35, ALNUM + "-_"))
SENDGRID = j("SG", ".", rand(22, ALNUM + "-_"), ".", rand(43, ALNUM + "-_"))
NPM = j("np", "m_", rand(36))
SENTRY_USER = j("sntr", "yu_", hexs(64))
RESEND = j("re", "_", rand(8), "_", rand(24))
LINEAR = j("lin", "_api_", rand(40))
HEROKU = j("HRKU", "-AA", rand(58, ALNUM + "_-"))
ONEPASSWORD_SA = j("ops", "_eyJ", rand(150, ALNUM + "+/"))
JWT = j("ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "J", rand(40, ALNUM + "-_"), ".", rand(43, ALNUM + "-_"))
PEM = j("-----BEGIN ", "PRIVATE KEY-----\n", rand(64, ALNUM + "+/"), "\n", rand(64, ALNUM + "+/"), "\n-----END ", "PRIVATE KEY-----")
RSA_PEM = j("-----BEGIN RSA ", "PRIVATE KEY-----\n", rand(64, ALNUM + "+/"), "\n-----END RSA ", "PRIVATE KEY-----")
DB_PASSWORD = rand(24)
DB_URL = j("postgres://app_user:", DB_PASSWORD, "@db.example.internal:5432/app")
SENTRY_DSN_KEY = hexs(32)
SENTRY_DSN = j("https://", SENTRY_DSN_KEY, "@o123456.ingest.us.sentry.io/4507")
GENERIC_TOKEN = rand(48)
BCRYPT = j("$2b$", "12$", rand(53, ALNUM + "./"))

# (text, the secret that must disappear from it)
MUST_MASK = [
    (f"STRIPE_API_KEY={STRIPE_LIVE}", STRIPE_LIVE),
    (f"key: {STRIPE_RESTRICTED}", STRIPE_RESTRICTED),
    (f"STRIPE_WEBHOOK_SECRET={STRIPE_WEBHOOK}", STRIPE_WEBHOOK),
    (f"git remote set-url origin https://{GITHUB_PAT}@github.com/a/b", GITHUB_PAT),
    (f"token={GITHUB_FINE}", GITHUB_FINE),
    (f"aws_access_key_id = {AWS_KEY_ID}", AWS_KEY_ID),
    (f'{{"bot_token": "{SLACK_BOT}"}}', SLACK_BOT),
    (f"export ANTHROPIC_API_KEY={ANTHROPIC}", ANTHROPIC),
    (f"OPENAI_API_KEY='{OPENAI}'", OPENAI),
    (f"maps?key={GOOGLE}&q=x", GOOGLE),
    (f"sendgrid {SENDGRID}", SENDGRID),
    (f"//registry.npmjs.org/:_authToken={NPM}", NPM),
    (f"auth.token={SENTRY_USER}", SENTRY_USER),
    (f"RESEND_API_KEY={RESEND}", RESEND),
    (f"LINEAR_API_KEY={LINEAR}", LINEAR),
    (f"HEROKU_API_KEY={HEROKU}", HEROKU),
    (f"OP_SERVICE_ACCOUNT_TOKEN={ONEPASSWORD_SA}", ONEPASSWORD_SA),
    (f"Authorization: Bearer {JWT}", JWT),
    (f"curl -H 'Authorization: Bearer {GENERIC_TOKEN}' https://api", GENERIC_TOKEN),
    (f"cookie: session={JWT}", JWT),
    (PEM, PEM),
    (RSA_PEM, RSA_PEM),
    (f'{{"private_key": "{PEM}"}}'.replace("\n", "\\n"), PEM.replace("\n", "\\n")),
    (f"DATABASE_URL={DB_URL}", DB_PASSWORD),
    (f"connecting to {DB_URL} ...", DB_PASSWORD),
    (f"SENTRY_DSN={SENTRY_DSN}", SENTRY_DSN_KEY),
    (f"psql --password {DB_PASSWORD} -h x", DB_PASSWORD),
    (f"mysql --password='{DB_PASSWORD}'", DB_PASSWORD),
    (f'password: "{DB_PASSWORD}"', DB_PASSWORD),
    (f"  db_password: {DB_PASSWORD}", DB_PASSWORD),
    ("PASSWORD=correcthorsebattery", "correcthorsebattery"),
    (f'const config = {{ apiKey: "{GENERIC_TOKEN}" }}', GENERIC_TOKEN),
    (f"clientSecret = '{rand(30)}'", None),
    (f"X-Api-Key: {GENERIC_TOKEN}", GENERIC_TOKEN),
    (f"https://example.com/cb?access_token={GENERIC_TOKEN}&state=1", GENERIC_TOKEN),
    (f"hash: {BCRYPT}", BCRYPT),
    (f"some log line {GENERIC_TOKEN} more", GENERIC_TOKEN),
    (f"\x1b[32mSECRET_KEY\x1b[0m={GENERIC_TOKEN}", GENERIC_TOKEN),
    # Review 2026-10-16: human passwords in YAML / compose / .properties, and
    # NAME=value lines as tools print them (cat -n, grep -n, git diff).
    ("password: Summer2024", "Summer2024"),
    ("POSTGRES_PASSWORD: Summer2024", "Summer2024"),
    ("      - POSTGRES_PASSWORD=Summer2024", "Summer2024"),
    ("spring.datasource.password=Summer2024", "Summer2024"),
    ("     1\tDB_PASSWORD=Summer2024", "Summer2024"),
    (".env:3:DB_PASSWORD=Summer2024", "Summer2024"),
    ("+DB_PASSWORD=Summer2024", "Summer2024"),
    # Review: short-form and veto-segment names.
    ("SMTP_PASS=Abc123def456", "Abc123def456"),
    ("PGPASSWORD=Abc123def456", "Abc123def456"),
    ("ADMINPASSWORD=Abc123def456", "Abc123def456"),
    ("PASSWORD2=Abc123def456", "Abc123def456"),
    ("MAILGUN_KEY=Abc123def456", "Abc123def456"),
    ("EMAIL_PROVIDER_API_KEY=Abc123def456", "Abc123def456"),
    ("URL_SIGNING_SECRET=Abc123def456", "Abc123def456"),
    ("FILE_ENCRYPTION_KEY=Abc123def456", "Abc123def456"),
    ("STATUS_PAGE_API_KEY=Abc123def456", "Abc123def456"),
    # Review: connection strings and cookies (a `;` separator is not code).
    ("Server=db;User Id=sa;Password=MyP4ss!;Encrypt=true", "MyP4ss!"),
    ("Driver={x};PWD=MyP4ss!;UID=sa", "MyP4ss!"),
    (f"Set-Cookie: sessionid={hexs(32)}; Path=/; HttpOnly", None),
    (j("DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=", rand(86, ALNUM + "+/"), "==;EndpointSuffix=core.windows.net"), None),
    # Review: empty username in a URL.
    ("REDIS_URL=redis://:S3cretRedisPw@cache.internal:6379", "S3cretRedisPw"),
    # Review: lowercase-hex vendor keys with no secret name nearby.
    (j('{"key": "', "sk-or-v1-", hexs(64), '"}'), None),
    (j("error: invalid key key-", hexs(32)), None),
    (j("using fc-", hexs(32), " for crawling"), None),
    # Review: long base64 (Kubernetes secrets) and truncated PEMs.
    (j("  tls.key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t", rand(200, ALNUM + "+/"), "=="), None),
    (j("-----BEGIN PRIVATE KEY-----\n", rand(64, ALNUM + "+/"), "\n", rand(64, ALNUM + "+/")), None),
    # Review: flags with a prefix, name/value pairs, .netrc, .pgpass.
    ("psql --db-password Summer2024x -h db", "Summer2024x"),
    ("deploy --admin-password=Summer2024x", "Summer2024x"),
    (j("gh auth --github-token ", GITHUB_PAT), GITHUB_PAT),
    ("- name: DB_PASSWORD\n  value: Summer2024", "Summer2024"),
    ('{"name": "API_KEY", "value": "Abc123def456"}', "Abc123def456"),
    ('{"Name": "/prod/db/password", "Value": "Abc123def456"}', "Abc123def456"),
    ("machine api.heroku.com login me@example.com password 0f8e1d2c-3b4a-4f5e-8d7c-6b5a49382716", "0f8e1d2c-3b4a-4f5e-8d7c-6b5a49382716"),
    ("localhost:5432:app:postgres:Summer2024x", "Summer2024x"),
    # Review: values with #, ; or < in strong context, and numeric passwords.
    ("DB_PASSWORD=abc#def123", "abc#def123"),
    ("DB_PASSWORD=ab<cd1234", "ab<cd1234"),
    ("DB_PASSWORD=12345678", "12345678"),
    # Review nit: a token right after a literal \n in JSON text.
    (j('{"msg": "line\\n', GITHUB_PAT, '"}'), GITHUB_PAT),
]

# Ordinary output that must come back unchanged.
MUST_NOT_MASK = [
    "commit 3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345",
    f"sha256:{hexs(64)}",
    "request_id=1b3261aa-e6e0-066c-eaf2-38707e223977",
    "max_tokens = 4096",
    '"max_tokens": 4096,',
    "token: expired",
    "password: String",
    "  password: z.string().min(8),",
    'tokenizer_path = "/models/tokenizer.json"',
    '"token_type": "Bearer",',
    '"expires_in": 3600,',
    "const token = getToken()",
    "token = request.headers.get('Authorization')",
    'api_key = os.environ["API_KEY"]',
    "API_KEY=${API_KEY}",
    "STRIPE_API_KEY=sk_test_xxx",
    "PASSWORD=changeme",
    "SECRET_KEY=your-secret-key",
    "password=<your password>",
    "DATABASE_URL=postgres://localhost:5432/app",
    "WEBAPP_BASE_URL=https://app.example.com",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY_NAME=checkout",
    "API_KEY_ID=key_123",
    "TOKEN_URL=https://auth.example.com/token",
    "SESSION_TTL=3600",
    "def get_token(self) -> str:",
    "if (!apiKey) throw new Error('API key missing')",
    "Authorization: Bearer ${TOKEN}",
    '"integrity": "sha512-' + rand(86, ALNUM + "+/") + '=="',
    "https://github.com/anthropics/claude-code/issues/32523",
    "src/components/OrderDetailsHeaderWithShippingSummary.tsx",
    "ERROR at=error code=H12 desc=\"Request timeout\" method=GET path=\"/orders/summary\"",
    "The password field is required.",
    "Set the token in your environment.",
    "export function useWidgetEndpoint() {",
    "x-request-id: 8b1c0e0f-4f6f-4e8e-9d39-3a2e1b0f7c55",
    "cus_NffrFeUfNV2Hib",
    "price_1NxSyz2eZvKYlo2CpsuQkWsZ",
    "docker pull ghcr.io/getsentry/action-release-image@sha256:" + hexs(64),
    "uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5",
    "a" * 200,
    "",
    # Code shapes seen while calibrating on a real TS/JS codebase (2026-10-16): identifiers,
    # expressions, types, UI copy, slugs, versions and commands next to secret names.
    "    accessToken: accessToken,",
    "    authToken: session2.token,",
    "  access_token: link.accessToken as string,",
    "const {getAccessToken: getProviderAccessToken} = useProviderAccessToken()",
    "export type WidgetFilters = z.infer<typeof widgetFilterSchema>",
    "const isActualTokenValid = token.length === 64",
    "    hasPassword: user.passwordHash !== null,",
    "  return {...projected, hasAccessToken: Boolean(details.accessToken)}",
    "routes={{otp: '/otp', forgotPassword: '/forgot-password'}}",
    "  passwordChanged: 'password-changed',",
    "export const AUTH_TOKEN_KEY = 'authToken'",
    "export type SecretKeyStatus = 'missing' | 'invalid' | 'ok'",
    "  currentPassword: 'Current password',",
    "  invalid_credentials: 'Invalid credentials, try again',",
    "const TOKEN_REFRESH_TIMEOUT_MS = 15_000",
    '    "cookie": "^0.7.1",',
    '    "rotate-secrets": "NODE_NO_WARNINGS=1 LOG_LEVEL=warn tsx ./src/scripts/rotateSecrets.ts",',
    "3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345:src/auth/sessionSecret.ts:generic-api-key:12",
    'customer_master_key_spec = "SYMMETRIC_DEFAULT"',
    "resetUrl: `${appBaseUrl}/set-new-password?token=${token}`",
    "DATABASE_URL: postgres://postgres:password@localhost:5432/app_test",
    "- https://owasp.org/Top10/A03_2021-Injection/",
    "// It's a bearer token-like value: short-lived, single-use",
]
