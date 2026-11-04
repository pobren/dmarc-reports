// API keys for the API (v1.ts) and the AI connector (mcp.ts), made in Settings. The key itself is only shown once:
// we keep a SHA-256 hash and its first few characters, so you can tell keys apart but nobody can see a whole key
// again. A key can be read only, or read and change (add domains and mark senders Mine or Not mine).

import { isoNow } from "./db.ts";

export const KEY_PREFIX = "dmarc_";
/** Keys an install can have. */
export const MAX_KEYS = 10;
/** Requests a minute for each key. */
export const API_LIMIT = 60;

const hexOf = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export const sha256 = async (text: string) => hexOf(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
/** A random hex string, `bytes` long before it's written out. */
export const randomHex = (bytes = 24) => hexOf(crypto.getRandomValues(new Uint8Array(bytes)).buffer);

/** Makes a key. The key itself is only ever returned here. */
export async function makeKey(db: D1Database, nameIn: unknown, change: boolean): Promise<{ key: string } | { error: string }> {
	const name = typeof nameIn === "string" ? nameIn.replace(/\s+/g, " ").trim().slice(0, 60) : "";
	if (!name) return { error: "Please give the key a name, such as Zapier or Monthly report, so you know which is which." };
	const count = await db.prepare("SELECT COUNT(*) AS n FROM api_keys").first<{ n: number }>();
	if ((count?.n ?? 0) >= MAX_KEYS) return { error: `You can have up to ${MAX_KEYS} keys. Delete one you no longer use first.` };
	const key = KEY_PREFIX + randomHex(24);
	await db.prepare("INSERT INTO api_keys (id, name, key_hash, hint, can_change, created_at) VALUES (?, ?, ?, ?, ?, ?)")
		.bind(randomHex(8), name, await sha256(key), key.slice(0, KEY_PREFIX.length + 4), change ? 1 : 0, isoNow()).run();
	return { key };
}

export async function listKeys(db: D1Database) {
	const { results } = await db.prepare("SELECT id, name, hint, can_change, created_at, last_used FROM api_keys ORDER BY created_at")
		.all<{ id: string; name: string; hint: string; can_change: number; created_at: string; last_used: string | null }>();
	return results.map((k) => ({ id: k.id, name: k.name, hint: k.hint, change: k.can_change === 1, createdAt: k.created_at, lastUsed: k.last_used }));
}

export const deleteKey = (db: D1Database, id: string) => db.prepare("DELETE FROM api_keys WHERE id = ?").bind(id).run();

/** The key sent with a request: Authorization: Bearer, or an X-API-Key header. */
export function keyFrom(request: Request): string {
	const bearer = /^Bearer\s+(\S+)$/i.exec((request.headers.get("authorization") ?? "").trim());
	return (bearer?.[1] ?? request.headers.get("x-api-key") ?? "").trim();
}

export type KeyCheck = { ok: true; change: boolean; remaining: number } | { ok: false; status: 401 | 429; error: string; wait?: number };

/** Checks a key and counts the request against its limit of API_LIMIT a minute. */
export async function checkKey(db: D1Database, key: string, now = Date.now()): Promise<KeyCheck> {
	const wrong = { ok: false as const, status: 401 as const, error: "That API key isn't right, or it has been deleted." };
	if (!key.startsWith(KEY_PREFIX)) return wrong;
	const found = await db.prepare("SELECT id, can_change FROM api_keys WHERE key_hash = ?").bind(await sha256(key)).first<{ id: string; can_change: number }>();
	if (!found) return wrong;
	const minute = Math.floor(now / 60_000) * 60_000;
	const used = await db
		.prepare("UPDATE api_keys SET window_count = CASE WHEN window_start = ? THEN window_count + 1 ELSE 1 END, window_start = ?, last_used = ? WHERE id = ? RETURNING window_count")
		.bind(minute, minute, new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z"), found.id)
		.first<{ window_count: number }>();
	const count = used?.window_count ?? 1;
	if (count > API_LIMIT) {
		const wait = Math.max(1, Math.ceil((minute + 60_000 - now) / 1000));
		return { ok: false, status: 429, wait, error: `Slow down: each key can make ${API_LIMIT} requests a minute. Try again in ${wait} seconds.` };
	}
	return { ok: true, change: found.can_change === 1, remaining: Math.max(0, API_LIMIT - count) };
}
