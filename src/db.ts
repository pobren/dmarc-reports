// The database, settings and a few small helpers every part of the app uses.

import { SCHEMA } from "./schema.ts";

export interface Env {
	DB: D1Database;
	/** The web pages in public/. */
	ASSETS: Fetcher;
	/** Sends alert and summary emails to your own verified address (Cloudflare Email Routing). Optional. */
	EMAIL?: SendEmail;
	/** The one-time code that lets you set your password (see the README). */
	SETUP_TOKEN?: string;
	/** Which release is running, set by the installer. */
	APP_VERSION?: string;
	/** Optional Cloudflare Turnstile on set-up and sign-in (turnstile.ts): both are needed, added as secrets. */
	TURNSTILE_SITE_KEY?: string;
	TURNSTILE_SECRET?: string;
}

export const NOW = "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')";
export const VERSION = "1.1.0";

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex", ...headers },
	});
}

/** A short random id from letters and digits that can't be confused with each other. */
export function newId(length = 10): string {
	const abc = "abcdefghjkmnpqrstuvwxyz23456789";
	return Array.from(crypto.getRandomValues(new Uint8Array(length)), (b) => abc[b % abc.length]).join("");
}

export const isoNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

/** Splits one schema entry into statements, without its comments. */
export function statements(sql: string): string[] {
	return sql
		.split("\n")
		.map((l) => l.replace(/--.*$/, ""))
		.join("\n")
		.split(/;\s*(?:\n|$)/)
		.map((s) => s.trim())
		.filter(Boolean);
}

let ready: Promise<void> | null = null;

/** Makes the tables the first time the app runs, and adds any new ones after an update. Once per Worker start. */
export function ensureSchema(db: D1Database): Promise<void> {
	ready ??= (async () => {
		await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)").run();
		const row = await db.prepare("SELECT value FROM settings WHERE key = 'schema'").first<{ value: string }>();
		const have = Number(row?.value ?? 0);
		for (let v = have; v < SCHEMA.length; v++) {
			await db.batch([
				...statements(SCHEMA[v]).map((s) => db.prepare(s)),
				db.prepare("INSERT INTO settings (key, value) VALUES ('schema', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").bind(String(v + 1)),
			]);
		}
	})().catch((e) => {
		ready = null;
		throw e;
	});
	return ready;
}

export async function getSetting(db: D1Database, key: string): Promise<string | null> {
	const row = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first<{ value: string }>();
	return row?.value ?? null;
}

export async function setSetting(db: D1Database, key: string, value: string | null): Promise<void> {
	if (value === null) await db.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();
	else await db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").bind(key, value).run();
}

/** The address mail providers send reports to, such as dmarc-reports@example.com. Null until it's set. */
export const reportAddress = (db: D1Database) => getSetting(db, "report_address");
