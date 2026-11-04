// The AI connector's addresses: /mcp itself, and the OAuth sign-in around it (/register, /token, /authorize and the
// two /.well-known files). An app such as Claude finds the sign-in on its own from the 401 that /mcp gives.

import { signedIn } from "./auth.ts";
import { brandOf } from "./brand.ts";
import type { Env } from "./db.ts";
import type { Resolve } from "./dns.ts";
import { checkKey, keyFrom, KEY_PREFIX, sha256 } from "./keys.ts";
import { handleMcp } from "./mcp.ts";
import { bearerAccount, checkAuthRequest, denied, issueCode, OAUTH_CORS, register, resourceMetadata, serverMetadata, token, unauthorised, type AuthRequest } from "./oauth.ts";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export const isConnectorPath = (p: string) => p === "/mcp" || p === "/register" || p === "/token" || p === "/authorize" || p.startsWith("/.well-known/oauth-");

/** Registrations from one address in a minute, before /register says slow down. */
const REGISTER_LIMIT = 10;
const recent = new Map<string, number[]>();
function tooMany(ip: string, now: number): boolean {
	const list = (recent.get(ip) ?? []).filter((t) => now - t < 60_000);
	list.push(now);
	recent.set(ip, list);
	if (recent.size > 1000) recent.clear();
	return list.length > REGISTER_LIMIT;
}

/** DMARC Reports has one owner, so every sign-in belongs to the same account. */
const OWNER = "owner";

export async function handleConnector(request: Request, env: Env, url: URL, resolve: Resolve, version: string): Promise<Response> {
	const p = url.pathname;
	const now = Date.now();
	const db = env.DB;
	if (p === "/authorize") return authorize(request, env, url, now);
	if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: OAUTH_CORS });
	if (p.startsWith("/.well-known/oauth-protected-resource")) return resourceMetadata(url.origin);
	if (p.startsWith("/.well-known/oauth-authorization-server")) return serverMetadata(url.origin);
	if (p === "/register" && request.method === "POST") {
		if (tooMany(request.headers.get("cf-connecting-ip") ?? "", now)) return Response.json({ error: "slow_down", error_description: "Too many apps registered from here. Try again in a minute." }, { status: 429, headers: OAUTH_CORS });
		return register(request, db, now);
	}
	if (p === "/token" && request.method === "POST") return token(request, db, now);
	if (p === "/mcp") {
		// An API key works too, for apps where you can add a header instead of signing in.
		const key = keyFrom(request);
		let accountId: string | null = null;
		if (key.startsWith(KEY_PREFIX)) {
			const check = await checkKey(db, key, now);
			if (!check.ok) return Response.json({ error: check.error }, { status: check.status, headers: OAUTH_CORS });
			accountId = OWNER;
		} else accountId = await bearerAccount(request, db, now);
		if (!accountId) return unauthorised(url.origin);
		const res = await handleMcp(request, db, resolve, version);
		for (const [k, v] of Object.entries(OAUTH_CORS)) res.headers.set(k, v);
		return res;
	}
	return new Response("Not found", { status: 404 });
}

const see = (location: string) => new Response(null, { status: 303, headers: { location, "cache-control": "no-store" } });
const sameOrigin = (request: Request, url: URL) => request.headers.get("origin") === url.origin || (request.headers.get("referer") ?? "").startsWith(url.origin + "/");
const consentToken = async (request: Request) => sha256(`${request.headers.get("cookie") ?? ""}:allow`);

async function authorize(request: Request, env: Env, url: URL, now: number): Promise<Response> {
	const db = env.DB;
	const params = request.method === "POST" ? new URLSearchParams((await request.formData()) as unknown as Record<string, string>) : url.searchParams;
	const brand = await brandOf(db);
	// Its own security headers: the form's answer sends the browser back to the app that asked (claude.ai, or
	// localhost for a desktop app), so form-action can't be limited to this site like the rest of the app.
	const page = (title: string, body: string, status = 200) =>
		new Response(
			`<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} · ${esc(brand.name)}</title><link rel="stylesheet" href="/app.css"></head>
<body><main class="wrap"><div class="panel narrow">${body}</div></main></body></html>`,
			{
				status,
				headers: {
					"content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "same-origin", "x-content-type-options": "nosniff", "x-robots-tag": "noindex, nofollow",
					"content-security-policy": "default-src 'none'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
				},
			},
		);
	const checked = await checkAuthRequest(db, params);
	if ("page" in checked) return page("Can't connect", `<h1>Can't connect</h1><p>${esc(checked.page)}</p>`, 400);
	if ("redirect" in checked) return see(checked.redirect);
	const req: AuthRequest = checked.ok;
	if (!(await signedIn(request, db))) {
		if (request.method === "POST") return new Response("Sign in first", { status: 401 });
		return see(`/?next=${encodeURIComponent(url.pathname + url.search)}`);
	}
	const csrf = await consentToken(request);
	if (request.method === "POST") {
		if (!sameOrigin(request, url) || params.get("csrf") !== csrf) return new Response("Forbidden", { status: 403 });
		if (params.get("decision") !== "allow") return see(denied(req));
		return see(await issueCode(db, req, OWNER, url.origin, now));
	}
	if (request.method !== "GET") return new Response("Method not allowed", { status: 405 });
	const keep = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "resource"]
		.filter((k) => params.has(k))
		.map((k) => `<input type="hidden" name="${k}" value="${esc(params.get(k))}">`)
		.join("");
	const where = new URL(req.redirectUri).hostname;
	const icon = (d: string) => `<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
	return page(
		"Allow access",
		`<h1>Let ${esc(req.clientName)} read ${esc(brand.name)}?</h1>
<form method="post" action="/authorize">${keep}<input type="hidden" name="csrf" value="${csrf}">
<p>${esc(req.clientName)} (${esc(where)}) will be able to see your domains, who sends email as them, how much passes and your TLS reports.</p>
<p class="small">It can't change anything. You can disconnect it at any time in Settings.</p>
<div class="acts"><button class="btn" type="submit" name="decision" value="allow">${icon('<path d="M4 10.5 8 14.5 16 6"/>')}<span>Allow</span></button><button class="btn quiet" type="submit" name="decision" value="deny">${icon('<path d="M5 5l10 10M15 5 5 15"/>')}<span>Cancel</span></button></div></form>`,
	);
}
