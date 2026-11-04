// Your own webhooks: a JSON POST to your address when a report arrives or an alert is due, made in Settings.
// Signed the same way as Mail App's and Site Watch's (DMARC-Reports-Signature: t=...,v1=...), so one check works for
// all three. A webhook that fails 10 times in a row is switched off; the Test button switches it back on.

import { isoNow } from "./db.ts";
import { randomHex } from "./keys.ts";

export const MAX_HOOKS = 5;
export const MAX_FAILS = 10;

/** What each event means. */
export const HOOK_TYPES = {
	"report.received": "A DMARC or TLS report arrived by email and was saved.",
	"sender.new": "Someone new started sending email as one of your domains (the New sender alert).",
	"sender.failing": "A sender that's yours started failing DMARC (the Your mail failing alert).",
	"reports.stopped": "No reports for 3 days (the Reports stopped alert).",
	"tls.failing": "Mail servers report email to you couldn't be sent encrypted (the Encryption failing alert).",
	test: "The Test button.",
} as const;
export type HookType = keyof typeof HOOK_TYPES;

/** The alert kinds in dmarc-core.ts, as webhook events. */
export const ALERT_TYPE: Record<string, HookType> = { new: "sender.new", failing: "sender.failing", silent: "reports.stopped", tls: "tls.failing" };

interface HookRow { id: string; url: string; secret: string; on_off: number; fails: number; last_status: string | null; created_at: string }

const hexOf = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

/** HMAC-SHA256 of "<timestamp>.<body>" with the webhook's secret, as hex. */
export async function signBody(secret: string, timestamp: string, body: string): Promise<string> {
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return hexOf(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${body}`)));
}

export async function hookHeaders(secret: string, type: string, delivery: string, body: string, now = Date.now()): Promise<Record<string, string>> {
	const ts = String(Math.floor(now / 1000));
	return {
		"content-type": "application/json",
		"user-agent": "DMARC-Reports",
		"dmarc-reports-event": type,
		"dmarc-reports-delivery": delivery,
		"dmarc-reports-signature": `t=${ts},v1=${await signBody(secret, ts, body)}`,
	};
}

export function cleanHookUrl(input: unknown): string | null {
	if (typeof input !== "string" || input.length > 500) return null;
	try {
		const u = new URL(input.trim());
		return u.protocol === "https:" && !u.username && !u.password ? u.toString() : null;
	} catch {
		return null;
	}
}

/** The address with its secret part hidden, for showing on the page. */
export function maskUrl(url: string): string {
	try {
		const u = new URL(url);
		const path = u.pathname.length > 12 ? `${u.pathname.slice(0, 8)}…` : u.pathname;
		return `${u.host}${path}`;
	} catch {
		return "";
	}
}

export async function listHooks(db: D1Database) {
	const { results } = await db.prepare("SELECT * FROM webhooks ORDER BY created_at").all<HookRow>();
	return results.map((h) => ({ id: h.id, where: maskUrl(h.url), secret: h.secret, on: h.on_off === 1, fails: h.fails, lastStatus: h.last_status, createdAt: h.created_at }));
}

export async function addHook(db: D1Database, urlIn: unknown): Promise<{ ok: true } | { error: string }> {
	const url = cleanHookUrl(urlIn);
	if (!url) return { error: "Please give the full address, starting with https://, so reports are encrypted on the way." };
	const n = await db.prepare("SELECT COUNT(*) AS n FROM webhooks").first<{ n: number }>();
	if ((n?.n ?? 0) >= MAX_HOOKS) return { error: `You can have up to ${MAX_HOOKS} webhooks. Remove one first.` };
	await db.prepare("INSERT INTO webhooks (id, url, secret, created_at) VALUES (?, ?, ?, ?)").bind(randomHex(8), url, `whsec_${randomHex(24)}`, isoNow()).run();
	return { ok: true };
}

/** Posts one event to one webhook. True when it answered 2xx within 10 seconds. */
async function post(db: D1Database, h: HookRow, type: HookType, data: Record<string, unknown>, app: string, now = new Date()): Promise<boolean> {
	const id = `evt_${randomHex(12)}`;
	const body = JSON.stringify({ id, type, created: now.toISOString().replace(/\.\d{3}Z$/, "Z"), app, data });
	let status = "no answer";
	try {
		const res = await fetch(h.url, { method: "POST", headers: await hookHeaders(h.secret, type, id, body, now.getTime()), body, signal: AbortSignal.timeout(10_000), redirect: "manual" });
		await res.body?.cancel();
		status = String(res.status);
	} catch {}
	const ok = /^2\d\d$/.test(status);
	const fails = ok ? 0 : h.fails + 1;
	await db.prepare("UPDATE webhooks SET fails = ?, on_off = ?, last_status = ? WHERE id = ?").bind(fails, ok ? 1 : fails >= MAX_FAILS ? 0 : h.on_off, `${status} at ${isoNow()}`, h.id).run();
	return ok;
}

/** Sends one event to every webhook that's switched on. */
export async function sendHooks(db: D1Database, type: HookType, data: Record<string, unknown>, app = "DMARC Reports"): Promise<void> {
	const { results } = await db.prepare("SELECT * FROM webhooks WHERE on_off = 1").all<HookRow>();
	for (const h of results) await post(db, h, type, data, app);
}

export async function testHook(db: D1Database, id: string, app = "DMARC Reports"): Promise<boolean | null> {
	const h = await db.prepare("SELECT * FROM webhooks WHERE id = ?").bind(id).first<HookRow>();
	if (!h) return null;
	return post(db, { ...h, on_off: 1 }, "test", { message: `If you can read this, ${app} webhooks will arrive here.` }, app);
}
