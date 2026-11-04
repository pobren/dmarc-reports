// Signing in. DMARC Reports has one owner: you. You set your password once with the set-up code (the
// SETUP_TOKEN secret), then sign in with it. A signed cookie keeps you signed in for 30 days.
//
//   GET  /api/me              Whether you're signed in, and whether the app has been set up yet
//   POST /api/setup           { code, password, reportAddress?, alertTo? }: set (or reset) your password
//   POST /api/sign-in         { password }
//   POST /api/sign-out
//   POST /api/password        { current, password }: change it while signed in

import { getSetting, json, setSetting, type Env } from "./db.ts";

const COOKIE = "dr_session";
const SESSION_DAYS = 30;
/** Workers allow up to 100,000 PBKDF2 rounds. */
const ROUNDS = 100_000;
/** Wrong passwords allowed from one place in 15 minutes, and from everywhere in an hour. */
const TRIES_PER_PLACE = 8;
const TRIES_EVERYWHERE = 40;
/** The example in .dev.vars.example and the Deploy button's form. Set-up stays locked until it's changed. */
const EXAMPLE_CODES = new Set(["change-me-to-a-long-random-code", "replace-this-with-your-own-long-code"]);
export const MIN_PASSWORD = 10;

const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));

/** True when both strings are the same, taking the same time whatever they hold. */
export function same(a: string, b: string): boolean {
	const x = enc.encode(a);
	const y = enc.encode(b);
	let diff = x.length ^ y.length;
	for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
	return diff === 0;
}

async function pbkdf2(password: string, salt: Uint8Array, rounds: number): Promise<string> {
	const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
	return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds }, key, 256));
}

/** "pbkdf2$<rounds>$<salt>$<hash>" */
export async function hashPassword(password: string, rounds = ROUNDS): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	return `pbkdf2$${rounds}$${hex(salt)}$${await pbkdf2(password, salt, rounds)}`;
}

export async function checkPassword(password: string, stored: string | null): Promise<boolean> {
	const [kind, rounds, salt, hash] = (stored ?? "").split("$");
	if (kind !== "pbkdf2" || !salt || !hash) return false;
	return same(await pbkdf2(password, unhex(salt), Number(rounds)), hash);
}

async function hmac(secret: string, text: string): Promise<string> {
	const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return hex(await crypto.subtle.sign("HMAC", key, enc.encode(text)));
}

/** The key that signs sign-in cookies. Made the first time it's needed; changing your password makes a new one, signing everyone out. */
async function sessionKey(db: D1Database): Promise<string> {
	let key = await getSetting(db, "session_key");
	if (!key) {
		key = hex(crypto.getRandomValues(new Uint8Array(32)));
		await setSetting(db, "session_key", key);
	}
	return key;
}

function cookieOf(request: Request, name: string): string | null {
	for (const part of (request.headers.get("cookie") ?? "").split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === name) return v.join("=");
	}
	return null;
}

const cookieLine = (value: string, maxAge: number) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

async function newSession(db: D1Database): Promise<string> {
	const until = Date.now() + SESSION_DAYS * 86_400_000;
	return cookieLine(`${until}.${await hmac(await sessionKey(db), String(until))}`, SESSION_DAYS * 86_400);
}

/** Whether the request comes from the signed-in owner. */
export async function signedIn(request: Request, db: D1Database): Promise<boolean> {
	const value = cookieOf(request, COOKIE);
	const m = value ? /^(\d{13})\.([0-9a-f]{64})$/.exec(value) : null;
	if (!m || Number(m[1]) < Date.now()) return false;
	const key = await getSetting(db, "session_key");
	return !!key && same(await hmac(key, m[1]), m[2]);
}

/** A hash of where a request comes from (never the address itself), for counting wrong passwords. */
async function placeOf(request: Request): Promise<string> {
	const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
	return hex(await crypto.subtle.digest("SHA-256", enc.encode(`dmarc-reports:${ip}`))).slice(0, 24);
}

async function tooManyTries(db: D1Database, who: string): Promise<boolean> {
	const r = await db.prepare(`SELECT
			(SELECT COUNT(*) FROM sign_ins WHERE who = ? AND ok = 0 AND at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-15 minutes')) AS here,
			(SELECT COUNT(*) FROM sign_ins WHERE ok = 0 AND at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour')) AS everywhere`).bind(who).first<{ here: number; everywhere: number }>();
	return (r?.here ?? 0) >= TRIES_PER_PLACE || (r?.everywhere ?? 0) >= TRIES_EVERYWHERE;
}

const noteTry = (db: D1Database, who: string, ok: boolean) => db.batch([
	db.prepare("INSERT INTO sign_ins (who, ok) VALUES (?, ?)").bind(who, ok ? 1 : 0),
	db.prepare("DELETE FROM sign_ins WHERE at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day')"),
]);

/** Whether a set-up code can be used: it's the SETUP_TOKEN, it isn't the example, it's long enough and it hasn't been used before. */
async function codeWorks(env: Env, code: unknown): Promise<"ok" | "locked" | "wrong" | "used"> {
	const token = (env.SETUP_TOKEN ?? "").trim();
	if (!token || token.length < 16 || EXAMPLE_CODES.has(token)) return "locked";
	if (typeof code !== "string" || !same(code.trim(), token)) return "wrong";
	const used = await getSetting(env.DB, "setup_used");
	if (used && same(used, await hmac("setup", token))) return "used";
	return "ok";
}

const body = (request: Request) => request.json<Record<string, unknown>>().catch(() => ({}) as Record<string, unknown>);
export const cleanEmail = (v: unknown) => (typeof v === "string" && /^[^\s@]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i.test(v.trim()) ? v.trim().toLowerCase() : null);

export async function me(request: Request, env: Env): Promise<Response> {
	const owner = !!(await getSetting(env.DB, "password"));
	const token = (env.SETUP_TOKEN ?? "").trim();
	return json({
		signedIn: owner && (await signedIn(request, env.DB)),
		setUp: owner,
		// Set-up can't start until SETUP_TOKEN is your own code.
		setupLocked: !token || token.length < 16 || EXAMPLE_CODES.has(token),
		version: env.APP_VERSION || undefined,
	});
}

/**
 * Sets your password with the set-up code. Also how you reset a forgotten password: put a new SETUP_TOKEN on
 * the Worker (running the installer again does this) and open the set-up link. Each code works once.
 */
export async function setup(request: Request, env: Env): Promise<Response> {
	const b = await body(request);
	const who = await placeOf(request);
	if (await tooManyTries(env.DB, who)) return json({ error: "Too many tries. Please wait 15 minutes and try again." }, 429);
	const works = await codeWorks(env, b.code);
	if (works === "locked") return json({ error: "Set-up is locked. Give the SETUP_TOKEN secret your own long code (16 characters or more) first: the README shows how." }, 403);
	if (works === "wrong") {
		await noteTry(env.DB, who, false);
		return json({ error: "That set-up code isn't right. Use the link the installer gave you, or the code you put in SETUP_TOKEN." }, 403);
	}
	if (works === "used") return json({ error: "That set-up code has already been used. To reset your password, give SETUP_TOKEN a new code and open the set-up link again." }, 403);
	const password = typeof b.password === "string" ? b.password : "";
	if (password.length < MIN_PASSWORD) return json({ error: `Please choose a password of at least ${MIN_PASSWORD} characters.` }, 400);
	if (password.length > 200) return json({ error: "That password is too long." }, 400);
	const report = b.reportAddress === undefined || b.reportAddress === "" ? undefined : cleanEmail(b.reportAddress);
	if (report === null) return json({ error: "The report address doesn't look like an email address." }, 400);
	const alertTo = b.alertTo === undefined || b.alertTo === "" ? undefined : cleanEmail(b.alertTo);
	if (alertTo === null) return json({ error: "The address for alerts doesn't look like an email address." }, 400);

	await setSetting(env.DB, "password", await hashPassword(password));
	// A new key signs everyone else out.
	await setSetting(env.DB, "session_key", hex(crypto.getRandomValues(new Uint8Array(32))));
	await setSetting(env.DB, "setup_used", await hmac("setup", (env.SETUP_TOKEN ?? "").trim()));
	if (report) await setSetting(env.DB, "report_address", report);
	if (alertTo) await setSetting(env.DB, "alert_to", alertTo);
	await noteTry(env.DB, who, true);
	return json({ ok: true }, 200, { "set-cookie": await newSession(env.DB) });
}

export async function signIn(request: Request, env: Env): Promise<Response> {
	const b = await body(request);
	const who = await placeOf(request);
	if (await tooManyTries(env.DB, who)) return json({ error: "Too many wrong passwords. Please wait 15 minutes and try again." }, 429);
	const stored = await getSetting(env.DB, "password");
	if (!stored) return json({ error: "DMARC Reports isn't set up yet. Open the set-up link first." }, 409);
	const ok = typeof b.password === "string" && b.password.length <= 200 && (await checkPassword(b.password, stored));
	await noteTry(env.DB, who, ok);
	if (!ok) return json({ error: "That password isn't right." }, 403);
	return json({ ok: true }, 200, { "set-cookie": await newSession(env.DB) });
}

export function signOut(): Response {
	return json({ ok: true }, 200, { "set-cookie": cookieLine("", 0) });
}

export async function changePassword(request: Request, env: Env): Promise<Response> {
	const b = await body(request);
	const who = await placeOf(request);
	if (await tooManyTries(env.DB, who)) return json({ error: "Too many tries. Please wait 15 minutes and try again." }, 429);
	const ok = typeof b.current === "string" && (await checkPassword(b.current, await getSetting(env.DB, "password")));
	if (!ok) {
		await noteTry(env.DB, who, false);
		return json({ error: "Your current password isn't right." }, 403);
	}
	const password = typeof b.password === "string" ? b.password : "";
	if (password.length < MIN_PASSWORD || password.length > 200) return json({ error: `Please choose a password of at least ${MIN_PASSWORD} characters.` }, 400);
	await setSetting(env.DB, "password", await hashPassword(password));
	await setSetting(env.DB, "session_key", hex(crypto.getRandomValues(new Uint8Array(32))));
	return json({ ok: true }, 200, { "set-cookie": await newSession(env.DB) });
}

