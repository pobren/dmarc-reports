// The install steps, run on the person's Cloudflare account with their API token. Every step checks what's
// already there first, so running it again is safe (that is also how updates work).
//
// Cloudflare API v4: D1 databases, Worker scripts and their assets, schedules, secrets, custom domains and
// Email Routing rules. https://developers.cloudflare.com/api/

import { CRON, DATABASE, LOCATIONS, SCRIPT, hostname, metadata, type Choice, type Manifest } from "./core.ts";

const API = "https://api.cloudflare.com/client/v4";
const ASSET_FILES_PER_REQUEST = 25;

export class InstallError extends Error {
	constructor(message: string, readonly detail?: string, readonly link?: { href: string; text: string }) {
		super(message);
	}
}

export interface CfResponse<T> {
	status: number;
	ok: boolean;
	result: T | null;
	errors: { code: number; message: string }[];
}

export async function call<T>(token: string, method: string, path: string, body?: unknown): Promise<CfResponse<T>> {
	const headers: Record<string, string> = { authorization: `Bearer ${token}` };
	let payload: BodyInit | undefined;
	if (body instanceof FormData) payload = body;
	else if (body !== undefined) {
		headers["content-type"] = "application/json";
		payload = JSON.stringify(body);
	}
	let res: Response;
	try {
		res = await fetch(`${API}${path}`, { method, headers, body: payload });
		if ([502, 503, 504].includes(res.status) && (method === "GET" || method === "PUT")) {
			await new Promise((r) => setTimeout(r, 2000));
			res = await fetch(`${API}${path}`, { method, headers, body: payload });
		}
	} catch (e) {
		throw new InstallError("We couldn't reach Cloudflare. Please check your connection and run the command again.", String(e));
	}
	const parsed = (await res.json().catch(() => null)) as { success?: boolean; result?: T; errors?: { code: number; message: string }[] } | null;
	return { status: res.status, ok: res.ok && Boolean(parsed?.success), result: parsed?.result ?? null, errors: parsed?.errors ?? [] };
}

export const describe = (r: CfResponse<unknown>) => `HTTP ${r.status}${r.errors.length ? ` (${r.errors.map((e) => `${e.code}: ${e.message}`).join("; ")})` : ""}`;

export function must<T>(r: CfResponse<T>, whatFailed: string): T {
	if (r.ok) return r.result as T;
	if (r.status === 401 || r.status === 403) {
		throw new InstallError(`${whatFailed} Cloudflare says your API token doesn't have permission. Check it has everything listed by npx @mrpwob/dmarc-reports help, then run the command again.`, describe(r));
	}
	throw new InstallError(whatFailed, describe(r));
}

/** Reads one of the release files that come inside the package. */
export type ReadFile = (path: string) => Promise<Uint8Array>;

export interface Context {
	token: string;
	choice: Choice;
	manifest: Manifest;
	read: ReadFile;
}

const acct = (ctx: Context) => `/accounts/${ctx.choice.accountId}`;

export async function installed(token: string, accountId: string): Promise<boolean> {
	return (await call(token, "GET", `/accounts/${accountId}/workers/scripts/${SCRIPT}/settings`)).ok;
}

export async function zoneId(ctx: Context): Promise<string> {
	const domain = ctx.choice.domain!;
	const zones = must(await call<{ id: string; name: string }[]>(ctx.token, "GET", `/zones?name=${encodeURIComponent(domain)}&account.id=${ctx.choice.accountId}`), `We couldn't find ${domain} on your Cloudflare account.`);
	const zone = zones?.find((z) => z.name.toLowerCase() === domain);
	if (!zone) throw new InstallError(`We couldn't find ${domain} on this Cloudflare account. Please check the domain and run the command again.`);
	return zone.id;
}

async function workersSubdomain(ctx: Context): Promise<string> {
	const r = await call<{ subdomain: string }>(ctx.token, "GET", `${acct(ctx)}/workers/subdomain`);
	if (r.ok && r.result?.subdomain) return r.result.subdomain;
	throw new InstallError("Your Cloudflare account doesn't have its free workers.dev address yet. Open Workers & Pages in your Cloudflare dashboard once, pick a name, then run the command again.", describe(r));
}

export async function hostFor(ctx: Context): Promise<string> {
	return ctx.choice.domain ? hostname(ctx.choice) : hostname(ctx.choice, await workersSubdomain(ctx));
}

async function findDatabase(ctx: Context): Promise<string | null> {
	const list = must(await call<{ uuid: string; name: string }[]>(ctx.token, "GET", `${acct(ctx)}/d1/database?name=${DATABASE}&per_page=100`), "We couldn't look at your databases.");
	return list?.find((d) => d.name === DATABASE)?.uuid ?? null;
}

/** 1. The database. The app makes its own tables the first time it runs. */
export async function database(ctx: Context): Promise<string> {
	const have = await findDatabase(ctx);
	if (have) return have;
	const made = must(await call<{ uuid: string }>(ctx.token, "POST", `${acct(ctx)}/d1/database`, { name: DATABASE, primary_location_hint: ctx.choice.location }),
		`We couldn't create the database in ${LOCATIONS[ctx.choice.location]}.`);
	return made.uuid;
}

const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");

/** 2. The web pages, then the Worker, bound to the database, with its schedule. */
export async function worker(ctx: Context, databaseId: string): Promise<void> {
	const manifest: Record<string, { hash: string; size: number }> = {};
	for (const a of ctx.manifest.assets) manifest[a.path] = { hash: a.hash, size: a.size };
	const session = must(await call<{ jwt: string; buckets: string[][] }>(ctx.token, "POST", `${acct(ctx)}/workers/scripts/${SCRIPT}/assets-upload-session`, { manifest }),
		"We couldn't start uploading DMARC Reports.");
	let jwt = session.jwt;
	const byHash = new Map(ctx.manifest.assets.map((a) => [a.hash, a]));
	const hashes = (session.buckets ?? []).flat();
	for (let i = 0; i < hashes.length; i += ASSET_FILES_PER_REQUEST) {
		const form = new FormData();
		for (const hash of hashes.slice(i, i + ASSET_FILES_PER_REQUEST)) {
			const a = byHash.get(hash);
			if (!a) throw new InstallError("This package's files don't match. Please run the command again with @latest.", `unknown asset ${hash}`);
			form.append(hash, new File([base64(await ctx.read(`assets${a.path}`))], hash, { type: a.contentType }));
		}
		const r = must(await call<{ jwt?: string }>(session.jwt, "POST", `${acct(ctx)}/workers/assets/upload?base64=true`, form), "We couldn't upload part of DMARC Reports.");
		if (r?.jwt) jwt = r.jwt;
	}
	const form = new FormData();
	form.append("metadata", new Blob([JSON.stringify(metadata(ctx.manifest, databaseId, jwt))], { type: "application/json" }));
	form.append("worker.mjs", new File([(await ctx.read("worker.mjs")) as BlobPart], "worker.mjs", { type: "application/javascript+module" }));
	must(await call(ctx.token, "PUT", `${acct(ctx)}/workers/scripts/${SCRIPT}`, form), "We couldn't install DMARC Reports.");
	must(await call(ctx.token, "PUT", `${acct(ctx)}/workers/scripts/${SCRIPT}/schedules`, [{ cron: CRON }]), "We couldn't set up the daily checks.");
}

/** 3. The app's address: dmarc.<domain>, or dmarc-reports.<subdomain>.workers.dev to try it. */
export async function address(ctx: Context): Promise<string> {
	const host = await hostFor(ctx);
	if (ctx.choice.domain) {
		const r = await call(ctx.token, "PUT", `${acct(ctx)}/workers/domains`, { environment: "production", hostname: host, service: SCRIPT, zone_id: await zoneId(ctx) });
		if (!r.ok && r.status === 409) throw new InstallError(`${host} is already in use. Remove its DNS record in Cloudflare, or pick another address with --subdomain, then run the command again.`, describe(r));
		must(r, `We couldn't set up ${host}.`);
	} else {
		must(await call(ctx.token, "POST", `${acct(ctx)}/workers/scripts/${SCRIPT}/subdomain`, { enabled: true }), "We couldn't switch on the app's address.");
	}
	return host;
}

/**
 * 4. Sends the report address to the Worker with an Email Routing rule. Only when Email Routing is already on for
 * the domain: switching it on changes the domain's mail servers, which would break email that's handled
 * elsewhere (such as Google Workspace), so that's left for the person to decide in the dashboard.
 */
export async function route(ctx: Context, report: string): Promise<{ routed: boolean; why?: string; link?: string }> {
	const zone = await zoneId(ctx);
	const link = `https://dash.cloudflare.com/${ctx.choice.accountId}/${ctx.choice.domain}/email/routing/overview`;
	const settings = await call<{ enabled?: boolean; status?: string }>(ctx.token, "GET", `/zones/${zone}/email/routing`);
	if (!settings.ok || !settings.result?.enabled) return { routed: false, why: "off", link };
	const rules = must(await call<{ id: string; matchers?: { type: string; field?: string; value?: string }[]; actions?: { type: string; value?: string[] }[] }[]>(ctx.token, "GET", `/zones/${zone}/email/routing/rules?per_page=50`),
		"We couldn't look at your Email Routing rules.");
	const mine = rules?.find((r) => r.matchers?.some((m) => m.type === "literal" && m.field === "to" && m.value?.toLowerCase() === report.toLowerCase()));
	const rule = { name: "DMARC Reports", enabled: true, matchers: [{ type: "literal", field: "to", value: report }], actions: [{ type: "worker", value: [SCRIPT] }] };
	if (mine) {
		if (mine.actions?.some((a) => a.type === "worker" && a.value?.includes(SCRIPT))) return { routed: true };
		return { routed: false, why: "taken", link };
	}
	must(await call(ctx.token, "POST", `/zones/${zone}/email/routing/rules`, rule), `We couldn't send ${report} to the app.`);
	return { routed: true };
}

export function newSetupToken(): string {
	return [...crypto.getRandomValues(new Uint8Array(24))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 5. A fresh set-up code on the Worker. Only the link that carries it can set the password. */
export async function setupCode(ctx: Context): Promise<string> {
	const token = newSetupToken();
	must(await call(ctx.token, "PUT", `${acct(ctx)}/workers/scripts/${SCRIPT}/secrets`, { name: "SETUP_TOKEN", text: token, type: "secret_text" }), "We couldn't lock the set-up to you.");
	return token;
}
