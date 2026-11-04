// The public API at /api/v1, for your own scripts, dashboards and tools such as Zapier, Make or n8n. Docs:
// https://paulobrien.dev/dmarc/api/ (the same rules as Mail App, ReaderCount and Site Watch).
//
//   GET  /api/v1                                what's here
//   GET  /api/v1/domains                        your domains, with the last 30 days' totals
//   POST /api/v1/domains                        add a domain: { "domain": "example.co.uk" } (a key that can change things)
//   GET  /api/v1/domains/{domain}               who sent email as it, how much passed and what to fix (?days=7, 30, 90 or 365)
//   GET  /api/v1/domains/{domain}/senders       every sender, with its verdict and fix (?days=)
//   POST /api/v1/domains/{domain}/senders       mark one Mine or Not mine: { "key": "...", "label": "mine" | "not" | null }
//   GET  /api/v1/domains/{domain}/reports       the latest reports that arrived (?limit=, up to 100)
//   GET  /api/v1/domains/{domain}/tls           TLS reports: how much mail to you was encrypted (?days=)
//
// Keys are made in Settings (keys.ts). Writes go through the same code as the app's own buttons. There are no CORS
// headers on purpose: a key belongs on a server, not in a web page.

import type { Analysis, SenderResult } from "./dmarc-core.ts";
import { reportAddress } from "./db.ts";
import type { Resolve } from "./dns.ts";
import { API_LIMIT, checkKey, KEY_PREFIX, keyFrom } from "./keys.ts";
import { cleanDmarcDomain, domainAnalysis, handleReports, periodOf, tlsRows } from "./reports.ts";
import { summariseTls } from "./tls-reports-core.ts";

export const DOCS = "https://paulobrien.dev/dmarc/api/";

const ENDPOINTS = [
	"GET /api/v1/domains", "POST /api/v1/domains", "GET /api/v1/domains/{domain}", "GET /api/v1/domains/{domain}/senders", "POST /api/v1/domains/{domain}/senders",
	"GET /api/v1/domains/{domain}/reports", "GET /api/v1/domains/{domain}/tls",
];

function answer(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex", ...headers },
	});
}
const problem = (status: number, error: string, headers: Record<string, string> = {}) => answer({ error, docs: DOCS }, status, headers);

const rate = (n: number, of: number) => (of ? Math.floor((n / of) * 100) : null);

/** One sender, as the API and the AI connector give it. */
export function apiSender(s: SenderResult) {
	return {
		key: s.key, name: s.name, label: s.label, known: s.known, status: s.status, title: s.title, summary: s.summary,
		messages: s.messages, passed: s.passed, passRate: rate(s.passed, s.messages), dkimAligned: s.dkimAligned, spfAligned: s.spfAligned, blocked: s.blocked,
		fix: s.fix ?? null, ips: s.ips.slice(0, 20),
	};
}

/** One domain's findings for a period. */
export function apiSummary(a: Analysis, days: number, record: string | null) {
	return {
		domain: a.domain, days, record, policy: a.policy, headline: a.headline, line: a.line,
		messages: a.messages, passed: a.passed, passRate: a.passRate, own: a.own, others: a.others, forwarded: a.forwarded,
		from: a.from, to: a.to, reporters: a.reporters, subdomains: a.subdomains,
		senders: a.senders.map((s) => ({ key: s.key, name: s.name, label: s.label, status: s.status, messages: s.messages, passed: s.passed, passRate: rate(s.passed, s.messages) })),
	};
}

export async function listDomains(db: D1Database) {
	const { results } = await db.prepare(`SELECT d.domain, d.created_at, d.record, d.stage,
			(SELECT COUNT(*) FROM reports r WHERE r.domain = d.domain AND r.source = 'mail' AND r.created_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')) AS reports,
			(SELECT COALESCE(SUM(messages), 0) FROM reports r WHERE r.domain = d.domain AND r.source = 'mail' AND r.created_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')) AS messages,
			(SELECT COALESCE(SUM(passed), 0) FROM reports r WHERE r.domain = d.domain AND r.source = 'mail' AND r.created_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')) AS passed
		FROM domains d ORDER BY d.domain`).all<{ domain: string; created_at: string; record: string | null; stage: number | null; reports: number; messages: number; passed: number }>();
	return {
		reportAddress: await reportAddress(db),
		domains: results.map((d) => ({ domain: d.domain, addedAt: d.created_at, record: d.record, last30Days: { reports: d.reports, messages: d.messages, passed: d.passed, passRate: rate(d.passed, d.messages) } })),
	};
}

export async function domainSummary(db: D1Database, domain: string, days: number) {
	const row = await db.prepare("SELECT record FROM domains WHERE domain = ?").bind(domain).first<{ record: string | null }>();
	if (!row) return null;
	return apiSummary(await domainAnalysis(db, domain, days), days, row.record);
}

export async function domainSenders(db: D1Database, domain: string, days: number) {
	return { domain, days, senders: (await domainAnalysis(db, domain, days)).senders.map(apiSender) };
}

export async function domainReports(db: D1Database, domain: string, limit: number) {
	const n = Math.min(100, Math.max(1, Math.floor(limit) || 30));
	const { results } = await db.prepare("SELECT org, report_id, begin_at, end_at, messages, passed, created_at FROM reports WHERE domain = ? AND source = 'mail' ORDER BY created_at DESC LIMIT ?")
		.bind(domain, n).all<{ org: string; report_id: string; begin_at: string | null; end_at: string | null; messages: number; passed: number; created_at: string }>();
	return { domain, reports: results.map((r) => ({ org: r.org, reportId: r.report_id, begin: r.begin_at, end: r.end_at, messages: r.messages, passed: r.passed, arrivedAt: r.created_at })) };
}

export async function domainTls(db: D1Database, domain: string, days: number) {
	return { domain, days, ...summariseTls(await tlsRows(db, domain, days), domain) };
}

/** Everything under /api/v1. */
export async function handleV1(request: Request, db: D1Database, resolve: Resolve): Promise<Response> {
	const url = new URL(request.url);
	const path = url.pathname.replace(/\/+$/, "") || "/api/v1";
	const method = request.method;
	if (path === "/api/v1") return answer({ name: "DMARC Reports API", version: "v1", docs: DOCS, endpoints: ENDPOINTS });
	if (url.searchParams.has("key") || url.searchParams.has("api_key")) {
		return problem(400, `Send your key in the Authorization header (Authorization: Bearer ${KEY_PREFIX}...), not in the address, where it ends up in logs and browser history.`);
	}
	const key = keyFrom(request);
	if (!key) return problem(401, `Add your API key: Authorization: Bearer ${KEY_PREFIX}... Make one in Settings, under API keys.`, { "www-authenticate": "Bearer" });
	const check = await checkKey(db, key);
	if (!check.ok) {
		const h: Record<string, string> = check.status === 401 ? { "www-authenticate": 'Bearer error="invalid_token"' } : { "retry-after": String(check.wait), "x-ratelimit-limit": String(API_LIMIT), "x-ratelimit-remaining": "0" };
		return problem(check.status, check.error, h);
	}
	const limits = { "x-ratelimit-limit": String(API_LIMIT), "x-ratelimit-remaining": String(check.remaining) };
	const ok = (body: unknown, status = 200) => answer(body, status, limits);
	const no = (status: number, error: string) => problem(status, error, limits);
	const days = periodOf(url.searchParams.get("days"));

	// Runs the app's own code for a change, and passes on any error it gives.
	const run = async (appPath: string, body: unknown) => {
		const res = (await handleReports(new Request(new URL(appPath, url.origin), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }), appPath, db, resolve))!;
		const data = await res.json<Record<string, unknown>>().catch(() => ({}) as Record<string, unknown>);
		return { ok: res.ok, status: res.status, data };
	};
	const change = async () => {
		if (method !== "POST") return no(405, "Use GET to read and POST to change.");
		if (!check.change) return no(403, "This key can only read. Make a key that can change things in Settings.");
		return null;
	};
	const body = method === "POST" ? await request.json<Record<string, unknown>>().catch(() => ({}) as Record<string, unknown>) : {};

	if (path === "/api/v1/domains") {
		if (method === "GET" || method === "HEAD") return ok(await listDomains(db));
		const stop = await change();
		if (stop) return stop;
		const r = await run("/api/domains", { domain: body.domain });
		if (!r.ok) return no(r.status, String(r.data.error ?? "That didn't work."));
		return ok({ domain: await domainSummary(db, String(r.data.domain), 30) }, 201);
	}
	const d = /^\/api\/v1\/domains\/([^/]+)(\/(senders|reports|tls))?$/.exec(path);
	if (d) {
		const domain = cleanDmarcDomain(decodeURIComponent(d[1]));
		if (!domain || !(await db.prepare("SELECT 1 FROM domains WHERE domain = ?").bind(domain).first())) return no(404, "That domain isn't in your list. Add it first.");
		const what = d[3] ?? "";
		if (method === "GET" || method === "HEAD") {
			if (what === "") return ok(await domainSummary(db, domain, days));
			if (what === "senders") return ok(await domainSenders(db, domain, days));
			if (what === "reports") return ok(await domainReports(db, domain, Number(url.searchParams.get("limit") ?? 30)));
			return ok(await domainTls(db, domain, days));
		}
		if (what === "senders") {
			const stop = await change();
			if (stop) return stop;
			const r = await run(`/api/domains/${encodeURIComponent(domain)}/labels`, { key: body.key, label: body.label });
			if (!r.ok) return no(r.status, String(r.data.error ?? "That didn't work."));
			return ok({ domain, key: body.key, label: body.label ?? null });
		}
		return no(405, "Use GET to read this.");
	}
	return no(404, `There's nothing at ${path}. See ${DOCS} for what there is.`);
}
