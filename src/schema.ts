// The database's tables. The app makes them itself the first time it runs (and adds anything new after an
// update), so there's no separate migration step: see ensureSchema() in src/db.ts.
// Each entry is one version's statements; only ever add new entries at the end.

export const SCHEMA: string[] = [
`-- DMARC Reports: everything the app keeps, in one D1 database on your own Cloudflare account.
-- Only what's read from each report is kept, never the report file itself.

-- The owner's settings: their password (hashed), the key that signs sign-in cookies, the report address
-- and where alert emails go. One row per setting.
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- Sign-in attempts, so passwords can't be guessed quickly. Kept for a day.
CREATE TABLE IF NOT EXISTS sign_ins (
	who TEXT NOT NULL,
	ok INTEGER NOT NULL DEFAULT 0,
	at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS sign_ins_at ON sign_ins (at);

-- Your domains.
CREATE TABLE IF NOT EXISTS domains (
	domain TEXT PRIMARY KEY,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
	-- The _dmarc TXT record last seen, its rollout step (-1 none, 0 watch only ... 4 reject), since when,
	-- and every step it has been seen on (comma separated).
	record TEXT,
	stage INTEGER,
	stage_since TEXT,
	stages_seen TEXT,
	checked_at TEXT,
	-- 1: email when the next rollout step is due; the step last emailed about.
	reminders INTEGER NOT NULL DEFAULT 1,
	reminded_stage INTEGER,
	-- 1: a summary email every week; when the last one went.
	weekly INTEGER NOT NULL DEFAULT 0,
	summary_at TEXT,
	-- Which alerts are on (JSON, see alertSettings) and what they've already said (JSON, see alertState).
	alerts TEXT,
	alert_state TEXT
);

-- Each report read: sent to the report address ("mail"), or uploaded ("upload", grouped by upload_id).
CREATE TABLE IF NOT EXISTS reports (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	source TEXT NOT NULL,
	upload_id TEXT,
	org TEXT NOT NULL,
	report_id TEXT NOT NULL,
	begin_at TEXT,
	end_at TEXT,
	-- The policy the report says it found (JSON, see Policy in src/dmarc-core.ts).
	policy TEXT NOT NULL,
	messages INTEGER NOT NULL DEFAULT 0,
	passed INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
-- The same report sent twice is only counted once.
CREATE UNIQUE INDEX IF NOT EXISTS reports_once ON reports (domain, org, report_id) WHERE source = 'mail';
CREATE INDEX IF NOT EXISTS reports_domain ON reports (domain, end_at);
CREATE INDEX IF NOT EXISTS reports_upload ON reports (upload_id);
CREATE INDEX IF NOT EXISTS reports_at ON reports (created_at);

-- One row per sending server in a report.
CREATE TABLE IF NOT EXISTS report_rows (
	report TEXT NOT NULL,
	ip TEXT NOT NULL,
	count INTEGER NOT NULL,
	disposition TEXT NOT NULL,
	dkim TEXT NOT NULL,
	spf TEXT NOT NULL,
	header_from TEXT,
	-- JSON: the DKIM signatures and SPF domain the receiver checked.
	dkim_auth TEXT NOT NULL DEFAULT '[]',
	spf_auth TEXT,
	sender_id TEXT NOT NULL,
	sender_name TEXT NOT NULL,
	ptr TEXT,
	-- Why a receiver let failing mail through (forwarded, mailing_list…), as JSON.
	reasons TEXT
);
CREATE INDEX IF NOT EXISTS report_rows_report ON report_rows (report);

-- Reverse DNS names of sending servers, so each one is only looked up once a month.
CREATE TABLE IF NOT EXISTS ips (
	ip TEXT PRIMARY KEY,
	ptr TEXT,
	looked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- What you said about a sender: "mine" or "not". key is SenderResult.key.
CREATE TABLE IF NOT EXISTS labels (
	domain TEXT NOT NULL,
	key TEXT NOT NULL,
	label TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
	PRIMARY KEY (domain, key)
);

-- Private read-only links to a domain's findings, for whoever looks after your email. They expire.
CREATE TABLE IF NOT EXISTS shares (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	days INTEGER NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- TLS reports (RFC 8460): how many connections to your mail servers were encrypted, and why any weren't.
CREATE TABLE IF NOT EXISTS tls_reports (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	org TEXT NOT NULL,
	report_id TEXT NOT NULL,
	begin_at TEXT,
	end_at TEXT,
	-- sts (MTA-STS), tlsa (DANE) or no-policy-found.
	policy_type TEXT NOT NULL,
	success INTEGER NOT NULL DEFAULT 0,
	failure INTEGER NOT NULL DEFAULT 0,
	-- JSON: up to 50 failure details (see TlsFailure in src/tls-reports-core.ts).
	details TEXT,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS tls_reports_once ON tls_reports (domain, org, report_id);
CREATE INDEX IF NOT EXISTS tls_reports_domain ON tls_reports (domain, end_at);
CREATE INDEX IF NOT EXISTS tls_reports_at ON tls_reports (created_at);
`,
`-- 1.2.0: API keys, webhooks and the AI connector's sign-in. Keys, codes and tokens are kept as SHA-256 hashes.

-- Keys for the API (src/v1.ts) and the AI connector. can_change 1: may add domains and mark senders.
CREATE TABLE IF NOT EXISTS api_keys (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
	hint TEXT NOT NULL,
	can_change INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
	last_used TEXT,
	window_start INTEGER NOT NULL DEFAULT 0,
	window_count INTEGER NOT NULL DEFAULT 0
);

-- Your own webhooks (src/hooks.ts): told about new reports and alerts, signed with their own secret.
CREATE TABLE IF NOT EXISTS webhooks (
	id TEXT PRIMARY KEY,
	url TEXT NOT NULL,
	secret TEXT NOT NULL,
	on_off INTEGER NOT NULL DEFAULT 1,
	fails INTEGER NOT NULL DEFAULT 0,
	last_status TEXT,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- The AI connector's OAuth sign-in (src/oauth.ts): apps that registered, one-time codes and tokens.
CREATE TABLE IF NOT EXISTS oauth_clients (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
	code_hash TEXT PRIMARY KEY,
	client_id TEXT NOT NULL,
	account_id TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	challenge TEXT NOT NULL,
	expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
	token_hash TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	client_id TEXT NOT NULL,
	account_id TEXT NOT NULL,
	expires INTEGER NOT NULL
);
`,
];
