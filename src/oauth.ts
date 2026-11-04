// OAuth 2.1 for the AI connector at /mcp (the same as ReaderCount's), so people add DMARC Reports to Claude or another
// MCP app and sign in with their DMARC Reports password instead of pasting a key. An API key also works at /mcp (mcp.ts).
// What Claude needs: protected-resource and authorisation-server metadata, dynamic client registration,
// the authorisation-code flow with PKCE (S256), refresh tokens, and a 401 that points at the metadata.
// Codes and tokens are only stored as SHA-256 hashes. Tokens can only read.

import { randomHex, sha256 } from "./keys.ts";

const randomToken = (bytes = 32) => randomHex(bytes);
/** Apps that registered but never signed in are cleared out past this many. */
const MAX_CLIENTS = 500;

const ACCESS_SECONDS = 3600;
const REFRESH_DAYS = 90;
const CODE_SECONDS = 600;
export const SCOPE = "dmarc:read";

export const OAUTH_CORS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Protocol-Version, Mcp-Session-Id",
	"Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...OAUTH_CORS, ...extra } });
}

export function resourceMetadata(origin: string): Response {
	return json({ resource: `${origin}/mcp`, authorization_servers: [origin], scopes_supported: [SCOPE], bearer_methods_supported: ["header"], resource_name: "DMARC Reports" });
}

export function serverMetadata(origin: string): Response {
	return json({
		issuer: origin,
		authorization_endpoint: `${origin}/authorize`,
		token_endpoint: `${origin}/token`,
		registration_endpoint: `${origin}/register`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		code_challenge_methods_supported: ["S256"],
		token_endpoint_auth_methods_supported: ["none"],
		scopes_supported: [SCOPE],
		service_documentation: "https://paulobrien.dev/dmarc/api/#ai",
	});
}

/** The reply to a connector request without a valid token: tells Claude where to sign in. */
export function unauthorised(origin: string): Response {
	return json({ error: "invalid_token", error_description: "Sign in to DMARC Reports to use this connector." }, 401, {
		"WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", scope="${SCOPE}"`,
	});
}

/** Only https addresses, or http on this computer (for desktop apps), with no tricks in them. */
export function goodRedirect(uri: unknown): uri is string {
	if (typeof uri !== "string" || uri.length > 500) return false;
	try {
		const u = new URL(uri);
		if (u.username || u.password || u.hash) return false;
		if (u.protocol === "https:") return true;
		return u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
	} catch {
		return false;
	}
}

/** Dynamic client registration (RFC 7591): Claude registers itself before the first sign-in. */
export async function register(request: Request, db: D1Database, now: number): Promise<Response> {
	let body: Record<string, unknown>;
	try {
		body = (await request.json()) as Record<string, unknown>;
	} catch {
		return json({ error: "invalid_client_metadata", error_description: "Send JSON." }, 400);
	}
	const uris = Array.isArray(body?.redirect_uris) ? body.redirect_uris : [];
	if (!uris.length || uris.length > 5 || !uris.every(goodRedirect)) {
		return json({ error: "invalid_redirect_uri", error_description: "Give one to five https redirect addresses." }, 400);
	}
	const method = body.token_endpoint_auth_method ?? "none";
	if (method !== "none") return json({ error: "invalid_client_metadata", error_description: "Only public clients (token_endpoint_auth_method none) are supported." }, 400);
	const name = String(body.client_name ?? "An app").replace(/[\u0000-\u001f<>]/g, "").slice(0, 80) || "An app";
	const id = "drc_" + randomToken(18);
	const many = await db.prepare("SELECT COUNT(*) AS n FROM oauth_clients").first<{ n: number }>();
	if ((many?.n ?? 0) >= MAX_CLIENTS) {
		await db.prepare("DELETE FROM oauth_clients WHERE id IN (SELECT c.id FROM oauth_clients c WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.id) ORDER BY c.created_at LIMIT 50)").run();
	}
	await db.prepare("INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)").bind(id, name, JSON.stringify(uris), now).run();
	return json(
		{
			client_id: id,
			client_id_issued_at: Math.floor(now / 1000),
			client_name: name,
			redirect_uris: uris,
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
		},
		201,
	);
}

export type AuthRequest = { clientId: string; clientName: string; redirectUri: string; challenge: string; state: string; scope: string };

/**
 * Checks an /authorize request. A bad client or redirect address is shown as a page (never redirected to);
 * other problems go back to the app as an OAuth error.
 */
export async function checkAuthRequest(db: D1Database, p: URLSearchParams): Promise<{ ok: AuthRequest } | { page: string } | { redirect: string }> {
	const clientId = p.get("client_id") ?? "";
	const redirectUri = p.get("redirect_uri") ?? "";
	const client = clientId ? await db.prepare("SELECT name, redirect_uris FROM oauth_clients WHERE id = ?").bind(clientId).first<{ name: string; redirect_uris: string }>() : null;
	if (!client) return { page: "This app isn't registered with DMARC Reports. Go back to it and try connecting again." };
	const allowed = JSON.parse(client.redirect_uris) as string[];
	if (!allowed.includes(redirectUri)) return { page: "This app gave an address DMARC Reports doesn't recognise. Go back to it and try connecting again." };
	const state = p.get("state") ?? "";
	const back = (error: string, description: string) => {
		const u = new URL(redirectUri);
		u.searchParams.set("error", error);
		u.searchParams.set("error_description", description);
		if (state) u.searchParams.set("state", state);
		return { redirect: u.toString() };
	};
	if (p.get("response_type") !== "code") return back("unsupported_response_type", "Only response_type=code is supported.");
	const challenge = p.get("code_challenge") ?? "";
	if (p.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) return back("invalid_request", "PKCE with S256 is required.");
	const scope = p.get("scope") ?? SCOPE;
	if (scope.split(" ").some((s) => s && s !== SCOPE)) return back("invalid_scope", `The only scope is ${SCOPE}.`);
	return { ok: { clientId, clientName: client.name, redirectUri, challenge, state, scope: SCOPE } };
}

/** After the person clicks Allow: a one-time code for the app, sent back on its redirect address. */
export async function issueCode(db: D1Database, req: AuthRequest, accountId: string, issuer: string, now: number): Promise<string> {
	const code = randomToken();
	await db
		.prepare("INSERT INTO oauth_codes (code_hash, client_id, account_id, redirect_uri, challenge, expires) VALUES (?, ?, ?, ?, ?, ?)")
		.bind(await sha256(code), req.clientId, accountId, req.redirectUri, req.challenge, now + CODE_SECONDS * 1000)
		.run();
	const u = new URL(req.redirectUri);
	u.searchParams.set("code", code);
	if (req.state) u.searchParams.set("state", req.state);
	u.searchParams.set("iss", issuer);
	return u.toString();
}

export function denied(req: AuthRequest): string {
	const u = new URL(req.redirectUri);
	u.searchParams.set("error", "access_denied");
	if (req.state) u.searchParams.set("state", req.state);
	return u.toString();
}

async function s256(verifier: string): Promise<string> {
	const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
	return btoa(String.fromCharCode(...d)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function tokens(db: D1Database, clientId: string, accountId: string, now: number): Promise<Response> {
	const access = randomToken();
	const refresh = randomToken();
	await db.batch([
		db.prepare("INSERT INTO oauth_tokens (token_hash, kind, client_id, account_id, expires) VALUES (?, 'access', ?, ?, ?)").bind(await sha256(access), clientId, accountId, now + ACCESS_SECONDS * 1000),
		db.prepare("INSERT INTO oauth_tokens (token_hash, kind, client_id, account_id, expires) VALUES (?, 'refresh', ?, ?, ?)").bind(await sha256(refresh), clientId, accountId, now + REFRESH_DAYS * 86_400_000),
	]);
	return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_SECONDS, refresh_token: refresh, scope: SCOPE });
}

/** The token endpoint: swaps a code (with its PKCE verifier) or a refresh token for new tokens. */
export async function token(request: Request, db: D1Database, now: number): Promise<Response> {
	let p: URLSearchParams;
	try {
		const type = request.headers.get("Content-Type") ?? "";
		p = type.includes("application/json") ? new URLSearchParams((await request.json()) as Record<string, string>) : new URLSearchParams(await request.text());
	} catch {
		return json({ error: "invalid_request" }, 400);
	}
	await db.batch([db.prepare("DELETE FROM oauth_codes WHERE expires < ?").bind(now), db.prepare("DELETE FROM oauth_tokens WHERE expires < ?").bind(now)]);
	const bad = (error = "invalid_grant", description = "That code or token isn't valid any more. Connect again.") => json({ error, error_description: description }, 400);
	const clientId = p.get("client_id") ?? "";
	const grant = p.get("grant_type");

	if (grant === "authorization_code") {
		const hash = await sha256(p.get("code") ?? "");
		// Deleting and reading in one step: two requests with the same code can't both get tokens.
		const row = await db.prepare("DELETE FROM oauth_codes WHERE code_hash = ? RETURNING client_id, account_id, redirect_uri, challenge, expires").bind(hash).first<{ client_id: string; account_id: string; redirect_uri: string; challenge: string; expires: number }>();
		if (!row) return bad();
		if (row.expires < now || row.client_id !== clientId || row.redirect_uri !== (p.get("redirect_uri") ?? "")) return bad();
		if ((await s256(p.get("code_verifier") ?? "")) !== row.challenge) return bad("invalid_grant", "The PKCE code verifier doesn't match.");
		return tokens(db, row.client_id, row.account_id, now);
	}
	if (grant === "refresh_token") {
		const hash = await sha256(p.get("refresh_token") ?? "");
		// Each refresh token works once (deleted as it's read, so two requests can't both use it).
		const row = await db.prepare("DELETE FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh' RETURNING client_id, account_id, expires").bind(hash).first<{ client_id: string; account_id: string; expires: number }>();
		if (!row || row.expires < now || (clientId && row.client_id !== clientId)) return bad();
		return tokens(db, row.client_id, row.account_id, now);
	}
	return bad("unsupported_grant_type", "Use authorization_code or refresh_token.");
}

/** The account a connector request's Bearer token belongs to, or null. */
export async function bearerAccount(request: Request, db: D1Database, now: number): Promise<string | null> {
	const m = /^Bearer\s+(\S+)$/i.exec(request.headers.get("Authorization") ?? "");
	if (!m) return null;
	const row = await db.prepare("SELECT account_id FROM oauth_tokens WHERE token_hash = ? AND kind = 'access' AND expires > ?").bind(await sha256(m[1]), now).first<{ account_id: string }>();
	return row?.account_id ?? null;
}

/** Has this account linked an AI app (a sign-in it can still renew)? */
export async function connectorLinked(db: D1Database, accountId: string, now: number): Promise<boolean> {
	return Boolean(await db.prepare("SELECT 1 FROM oauth_tokens WHERE account_id = ? AND kind = 'refresh' AND expires > ? LIMIT 1").bind(accountId, now).first());
}

/** Disconnects every AI app from an account (the Disconnect button). */
export async function revokeAll(db: D1Database, accountId: string): Promise<void> {
	await db.prepare("DELETE FROM oauth_tokens WHERE account_id = ?").bind(accountId).run();
}
