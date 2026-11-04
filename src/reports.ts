// Your domains and their reports: keeping what each report says, and the views the app shows.
// The rules (reading reports, naming senders, the rollout plan) are in dmarc-core.ts.
//
//   GET    /api/domains                          Your domains, with the last 30 days in brief, and your uploads
//   POST   /api/domains                          { domain }: add one
//   GET    /api/domains/<d>?days=30&day=          Everything about one domain
//   DELETE /api/domains/<d>                       Remove it and its reports
//   POST   /api/domains/<d>/settings             { reminders?, weekly?, alert?, on? }
//   POST   /api/domains/<d>/labels               { key, label: "mine" | "not" | null }
//   POST   /api/domains/<d>/share                { days }: a private read-only link
//   GET    /api/domains/<d>/rows?days=&result=&sender=&org=&selector=&disposition=&offset=
//   GET    /api/domains/<d>/export?days=...      The same rows as a CSV file
//   GET    /api/domains/<d>/tls?days=30          TLS reports
//   POST   /api/upload                           Report files (multipart, "file" fields)
//   GET    /api/uploads/<id>   DELETE /api/uploads/<id>
//   GET    /api/share/<id>                       A shared domain's findings, for anyone with the link

import {
	alertSettings, analyse, byDay, CSV_HEAD, csvRow, dmarcRecord, filterRows, parseDmarc, parseReport, ptrName, ReportError, rollout, rowFilter,
	senderFor, stageOf, unpackReport, MAX_FILE,
	type Analysis, type DmarcAlert, type Policy, type Report, type SenderLabel, type StoredRow,
} from "./dmarc-core.ts";
import { summariseTls, tlsRecord, tlsRecordHasUs, type TlsRow } from "./tls-reports-core.ts";
import { cleanDomain, dnsHostFor, joinTxt, recordSteps, type Resolve } from "./dns.ts";
import { json, newId, NOW, isoNow, reportAddress } from "./db.ts";

/** Reports are kept for 12 months. */
export const KEEP_DAYS = 365;
/** Files in one upload. */
const FILES_PER_UPLOAD = 10;
/** Reverse DNS lookups for one report; any more servers are named from DKIM and SPF only. */
const PTR_LOOKUPS = 40;
/** The licence's free limit (see LICENSE). Nothing stops you going past it; the app just mentions it. */
export const FREE_DOMAINS = 10;
const PERIODS = [7, 30, 90, KEEP_DAYS];
const SHARE_DAYS = 14;

/** A domain as people type it, without www. */
export function cleanDmarcDomain(input: unknown): string | null {
	const d = cleanDomain(input);
	return d ? d.replace(/^www\./, "") : null;
}

export const periodOf = (v: unknown) => (PERIODS.includes(Number(v)) ? Number(v) : 30);

// --- Keeping reports ------------------------------------------------------------------------------

/** Reverse DNS names for a report's servers: from the cache, else looked up (at most PTR_LOOKUPS). */
async function ptrsFor(db: D1Database, ips: string[], resolve: Resolve): Promise<Map<string, string | null>> {
	const out = new Map<string, string | null>();
	const unique = [...new Set(ips)].slice(0, 500);
	for (let i = 0; i < unique.length; i += 50) {
		const chunk = unique.slice(i, i + 50);
		const { results } = await db.prepare(`SELECT ip, ptr FROM ips WHERE ip IN (${chunk.map(() => "?").join(",")}) AND looked_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')`)
			.bind(...chunk).all<{ ip: string; ptr: string | null }>();
		for (const r of results) out.set(r.ip, r.ptr);
	}
	const todo = unique.filter((ip) => !out.has(ip) && ptrName(ip)).slice(0, PTR_LOOKUPS);
	const found = await Promise.all(todo.map(async (ip) => {
		const a = await resolve(ptrName(ip)!, "PTR");
		return [ip, a.status === 0 && a.data[0] ? a.data[0].replace(/\.$/, "").toLowerCase().slice(0, 253) : null] as const;
	}));
	for (const [ip, ptr] of found) out.set(ip, ptr);
	if (found.length) {
		await db.batch(found.map(([ip, ptr]) => db.prepare("INSERT INTO ips (ip, ptr) VALUES (?, ?) ON CONFLICT (ip) DO UPDATE SET ptr = excluded.ptr, looked_at = excluded.looked_at").bind(ip, ptr)));
	}
	return out;
}

/** Saves one report and its rows under `domain`. False when it was already saved (the same report sent twice). */
export async function saveReport(db: D1Database, domain: string, report: Report, source: "mail" | "upload", uploadId: string | null, resolve: Resolve): Promise<boolean> {
	const ptrs = await ptrsFor(db, report.rows.map((r) => r.ip), resolve);
	const id = newId(16);
	const messages = report.rows.reduce((n, r) => n + r.count, 0);
	const passed = report.rows.reduce((n, r) => n + (r.dkim === "pass" || r.spf === "pass" ? r.count : 0), 0);
	const added = await db.prepare(`INSERT OR IGNORE INTO reports (id, domain, source, upload_id, org, report_id, begin_at, end_at, policy, messages, passed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		.bind(id, domain, source, uploadId, report.org, report.reportId || id, report.begin || null, report.end || null, JSON.stringify(report.policy), messages, passed).run();
	if (!added.meta.changes) return false;
	const rows = report.rows.map((r) => {
		const ptr = ptrs.get(r.ip) ?? null;
		const s = senderFor(r, report.policy.domain, ptr);
		return db.prepare(`INSERT INTO report_rows (report, ip, count, disposition, dkim, spf, header_from, dkim_auth, spf_auth, sender_id, sender_name, ptr, reasons)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
			.bind(id, r.ip, r.count, r.disposition, r.dkim, r.spf, r.headerFrom, JSON.stringify(r.dkimAuth), r.spfAuth ? JSON.stringify(r.spfAuth) : null, s.id, s.name, ptr,
				r.reasons?.length ? JSON.stringify(r.reasons) : null);
	});
	for (let i = 0; i < rows.length; i += 100) await db.batch(rows.slice(i, i + 100));
	return true;
}

interface JoinedRow {
	rid: string;
	org: string;
	begin_at: string | null;
	end_at: string | null;
	policy: string;
	ip: string;
	count: number;
	disposition: string;
	dkim: string;
	spf: string;
	header_from: string | null;
	dkim_auth: string;
	spf_auth: string | null;
	sender_id: string;
	sender_name: string;
	ptr: string | null;
	reasons: string | null;
}

/** Turns stored rows back into reports for analyse(). */
function regroup(rows: JoinedRow[]) {
	const reports = new Map<string, { org: string; begin: string; end: string; policy: Policy; rows: StoredRow[] }>();
	for (const r of rows) {
		let rep = reports.get(r.rid);
		if (!rep) {
			rep = { org: r.org, begin: r.begin_at ?? "", end: r.end_at ?? "", policy: JSON.parse(r.policy), rows: [] };
			reports.set(r.rid, rep);
		}
		rep.rows.push({
			ip: r.ip, count: r.count, disposition: r.disposition, dkim: r.dkim === "pass" ? "pass" : "fail", spf: r.spf === "pass" ? "pass" : "fail",
			headerFrom: r.header_from ?? "", dkimAuth: JSON.parse(r.dkim_auth), spfAuth: r.spf_auth ? JSON.parse(r.spf_auth) : null,
			ptr: r.ptr, sender: { id: r.sender_id, name: r.sender_name, known: r.sender_id !== "other" }, reasons: r.reasons ? JSON.parse(r.reasons) : [],
		});
	}
	return [...reports.values()];
}

const JOIN = `SELECT r.id AS rid, r.org, r.begin_at, r.end_at, r.policy, w.ip, w.count, w.disposition, w.dkim, w.spf, w.header_from, w.dkim_auth, w.spf_auth, w.sender_id, w.sender_name, w.ptr, w.reasons
	FROM reports r JOIN report_rows w ON w.report = r.id`;

/** The reports (as analyse() takes them) and your sender labels for a period: from `days` ago to `untilDaysAgo` days ago. */
export async function domainReports(db: D1Database, domain: string, days: number, untilDaysAgo = 0) {
	const labels = await labelsFor(db, domain);
	const { results } = await db.prepare(`${JOIN} WHERE r.domain = ? AND r.source = 'mail' AND COALESCE(r.end_at, r.created_at) > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)
		AND COALESCE(r.end_at, r.created_at) <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) LIMIT 50000`)
		.bind(domain, `-${days} days`, `-${untilDaysAgo} days`).all<JoinedRow>();
	return { reports: regroup(results), labels };
}

export async function domainAnalysis(db: D1Database, domain: string, days: number, untilDaysAgo = 0): Promise<Analysis> {
	const { reports, labels } = await domainReports(db, domain, days, untilDaysAgo);
	return analyse(domain, reports, labels);
}

async function labelsFor(db: D1Database, domain: string): Promise<Map<string, SenderLabel>> {
	const { results } = await db.prepare("SELECT key, label FROM labels WHERE domain = ?").bind(domain).all<{ key: string; label: SenderLabel }>();
	return new Map(results.map((r) => [r.key, r.label]));
}

// --- DNS: records and the rollout -----------------------------------------------------------------

/** Who runs the domain's DNS, and the zone it sits in (walking up from a subdomain). */
export async function dnsHost(domain: string, resolve: Resolve) {
	const parts = domain.split(".");
	for (let i = 0; i < parts.length - 1; i++) {
		const name = parts.slice(i).join(".");
		const a = await resolve(name, "NS");
		if (a.status === 0 && a.data.length) return { zone: name, host: dnsHostFor(a.data) };
	}
	return { zone: domain, host: null };
}

/** The domain's DMARC record as the world sees it, or null. */
export async function currentRecord(domain: string, resolve: Resolve): Promise<string | null> {
	const a = await resolve(`_dmarc.${domain}`, "TXT");
	return a.data.map((d) => joinTxt(d).trim()).find((d) => /^v=DMARC1\b/i.test(d)) ?? null;
}

/** The domain's TLS reporting record (_smtp._tls), or null. */
export async function currentTlsRecord(domain: string, resolve: Resolve): Promise<string | null> {
	const a = await resolve(`_smtp._tls.${domain}`, "TXT");
	return a.data.map((d) => joinTxt(d).trim()).find((v) => /^v=TLSRPTv1/i.test(v)) ?? null;
}

/**
 * When the report address is on another domain, that domain has to say it's happy to take reports for this one
 * (RFC 7489 section 7.1): a TXT record "v=DMARC1" at <domain>._report._dmarc.<report address domain>. Mail providers
 * check it before they send. Null when it isn't needed.
 */
export function externalRecordName(domain: string, address: string): string | null {
	const at = address.split("@")[1]?.toLowerCase();
	if (!at || domain === at || domain.endsWith(`.${at}`)) return null;
	return `${domain}._report._dmarc.${at}`;
}

async function externalOk(name: string, resolve: Resolve): Promise<boolean> {
	const a = await resolve(name, "TXT");
	return a.data.map((d) => joinTxt(d).trim()).some((v) => /^v=DMARC1\b/i.test(v));
}

export interface DomainRow {
	domain: string;
	created_at: string;
	record: string | null;
	stage: number | null;
	stage_since: string | null;
	stages_seen: string | null;
	checked_at: string | null;
	reminders: number;
	reminded_stage: number | null;
	weekly: number;
	summary_at: string | null;
	alerts: string | null;
	alert_state: string | null;
}

/** Looks the record up and notes when its rollout step changed. */
export async function refreshRecord(db: D1Database, row: DomainRow, resolve: Resolve): Promise<{ record: string | null; stage: number; since: string | null; seen: number[] }> {
	const record = await currentRecord(row.domain, resolve);
	const tags = record ? parseDmarc(record) : null;
	const pct = Number(tags?.get("pct"));
	const stage = tags ? stageOf(tags.get("p")?.toLowerCase(), tags.has("pct") && Number.isFinite(pct) ? pct : 100) : -1;
	const changed = stage !== row.stage;
	const seen = [...new Set([...(row.stages_seen ?? "").split(",").filter(Boolean).map(Number), stage])].filter((n) => n >= 0).sort();
	await db.prepare(`UPDATE domains SET record = ?, stage = ?, stage_since = CASE WHEN ? THEN ${NOW} ELSE stage_since END, stages_seen = ?, checked_at = ${NOW} WHERE domain = ?`)
		.bind(record, stage, changed ? 1 : 0, seen.join(","), row.domain).run();
	return { record, stage, since: changed ? isoNow() : row.stage_since, seen };
}

// --- The views ---------------------------------------------------------------------------------------

const SINCE_30 = "r.created_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')";

async function listDomains(db: D1Database): Promise<Response> {
	const { results } = await db.prepare(`SELECT d.domain, d.created_at, d.record, d.stage,
			(SELECT COUNT(*) FROM reports r WHERE r.domain = d.domain AND r.source = 'mail' AND ${SINCE_30}) AS reports,
			(SELECT COALESCE(SUM(messages), 0) FROM reports r WHERE r.domain = d.domain AND r.source = 'mail' AND ${SINCE_30}) AS messages,
			(SELECT COALESCE(SUM(passed), 0) FROM reports r WHERE r.domain = d.domain AND r.source = 'mail' AND ${SINCE_30}) AS passed
		FROM domains d ORDER BY d.domain`).all<Record<string, unknown>>();
	const uploads = await db.prepare(`SELECT upload_id AS id, MIN(created_at) AS at, GROUP_CONCAT(DISTINCT domain) AS domains, COUNT(*) AS reports, SUM(messages) AS messages, SUM(passed) AS passed
		FROM reports WHERE source = 'upload' GROUP BY upload_id ORDER BY at DESC LIMIT 20`).all<Record<string, unknown>>();
	const address = await reportAddress(db);
	return json({ address, domains: results, uploads: uploads.results, freeDomains: FREE_DOMAINS });
}

async function addDomain(request: Request, db: D1Database): Promise<Response> {
	const b = await request.json<{ domain?: unknown }>().catch(() => ({}) as { domain?: unknown });
	const domain = cleanDmarcDomain(b.domain);
	if (!domain) return json({ error: "Please enter a valid domain name, such as example.co.uk." }, 400);
	await db.prepare("INSERT OR IGNORE INTO domains (domain) VALUES (?)").bind(domain).run();
	return json({ domain });
}

async function domainView(url: URL, db: D1Database, domain: string, resolve: Resolve): Promise<Response> {
	const row = await db.prepare("SELECT * FROM domains WHERE domain = ?").bind(domain).first<DomainRow>();
	if (!row) return json({ error: "That domain isn't in your list." }, 404);
	const address = await reportAddress(db);
	const days = periodOf(url.searchParams.get("days"));
	// ?day=YYYY-MM-DD: the senders on one day of the period, for a click on the chart.
	const day = /^\d{4}-\d{2}-\d{2}$/.test(url.searchParams.get("day") ?? "") ? url.searchParams.get("day")! : null;
	const external = address ? externalRecordName(domain, address) : null;
	const [{ record, since, seen }, where, period, recent, reports, daily, authorised] = await Promise.all([
		refreshRecord(db, row, resolve),
		dnsHost(domain, resolve),
		domainReports(db, domain, days),
		domainAnalysis(db, domain, 14),
		db.prepare("SELECT org, begin_at, end_at, messages, passed, created_at FROM reports WHERE domain = ? AND source = 'mail' ORDER BY created_at DESC LIMIT 30").bind(domain).all(),
		// Emails and passes per day, for the chart (a report counts on the day it ends).
		db.prepare(`SELECT substr(COALESCE(end_at, created_at), 1, 10) AS day, SUM(messages) AS messages, SUM(passed) AS passed FROM reports
			WHERE domain = ? AND source = 'mail' AND COALESCE(end_at, created_at) > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) GROUP BY day ORDER BY day`)
			.bind(domain, `-${days} days`).all<{ day: string; messages: number; passed: number }>(),
		external ? externalOk(external, resolve) : Promise.resolve(true),
	]);
	const analysis = analyse(domain, day ? period.reports.filter((r) => r.end.slice(0, 10) === day) : period.reports, period.labels);
	const name = where.zone === domain ? "_dmarc" : `_dmarc.${domain.slice(0, -(where.zone.length + 1))}`;
	const hasUs = !!(address && record && (parseDmarc(record).get("rua") ?? "").toLowerCase().includes(`mailto:${address.toLowerCase()}`));
	// What to paste now: their record with the report address added, or a new watch-only one.
	const tags = record ? parseDmarc(record) : null;
	const suggested = address ? dmarcRecord(record, address, tags?.get("p")?.toLowerCase() || "none", Number(tags?.get("pct")) || 100) : null;
	const setup = suggested && !hasUs ? {
		record: { type: "TXT", name, value: suggested, action: record ? "edit" : "add" },
		steps: recordSteps(where.host, where.zone, [{ type: "TXT", name, value: suggested, action: record ? "edit" : "add" }]).slice(0, -1),
		host: where.host ? { name: where.host.name, panel: where.host.where ?? null } : null,
	} : null;
	return json({
		domain, created: row.created_at, reminders: !!row.reminders, weekly: !!row.weekly, alerts: alertSettings(row.alerts),
		address, record, hasUs, setup, days, day,
		// The report address is on another domain: the record that domain needs, and whether it's there.
		external: external ? { name: external, value: "v=DMARC1", ok: authorised } : null,
		analysis,
		byDay: byDay(domain, period.reports),
		rollout: address ? rollout({ record, report: address, since, recent, seen }) : null,
		reports: reports.results,
		daily: daily.results,
	});
}

async function domainSettings(request: Request, db: D1Database, domain: string): Promise<Response> {
	const b = await request.json<Record<string, unknown>>().catch(() => ({}) as Record<string, unknown>);
	let alerts: string | null = null;
	// One alert switch at a time: { alert: "new" | "failing" | "silent" | "tls" | "mineOnly", on: true | false }.
	if (typeof b.alert === "string" && ["new", "failing", "silent", "tls", "mineOnly"].includes(b.alert) && typeof b.on === "boolean") {
		const row = await db.prepare("SELECT alerts FROM domains WHERE domain = ?").bind(domain).first<{ alerts: string | null }>();
		alerts = JSON.stringify({ ...alertSettings(row?.alerts), [b.alert as DmarcAlert | "mineOnly"]: b.on });
	}
	await db.prepare("UPDATE domains SET reminders = COALESCE(?, reminders), weekly = COALESCE(?, weekly), alerts = COALESCE(?, alerts) WHERE domain = ?")
		.bind(typeof b.reminders === "boolean" ? Number(b.reminders) : null, typeof b.weekly === "boolean" ? Number(b.weekly) : null, alerts, domain).run();
	return json({ ok: true, alerts: alerts ? alertSettings(alerts) : undefined });
}

async function setLabel(request: Request, db: D1Database, domain: string): Promise<Response> {
	const b = await request.json<{ key?: unknown; label?: unknown }>().catch(() => ({}) as Record<string, unknown>);
	const key = typeof b.key === "string" ? b.key.slice(0, 200) : "";
	if (!key || key === "forwarded") return json({ error: "Please choose a sender." }, 400);
	if (b.label === null) await db.prepare("DELETE FROM labels WHERE domain = ? AND key = ?").bind(domain, key).run();
	else if (b.label === "mine" || b.label === "not") {
		await db.prepare("INSERT INTO labels (domain, key, label) VALUES (?, ?, ?) ON CONFLICT (domain, key) DO UPDATE SET label = excluded.label").bind(domain, key, b.label).run();
	} else return json({ error: "A sender is either mine or not mine." }, 400);
	return json({ ok: true });
}

async function shareDomain(request: Request, db: D1Database, domain: string): Promise<Response> {
	const b = await request.json<{ days?: unknown }>().catch(() => ({}) as Record<string, unknown>);
	const days = periodOf(b.days);
	const id = newId(20);
	const expires = new Date(Date.now() + SHARE_DAYS * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
	await db.batch([
		db.prepare("DELETE FROM shares WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"),
		db.prepare("INSERT INTO shares (id, domain, days, expires_at) VALUES (?, ?, ?, ?)").bind(id, domain, days, expires),
	]);
	return json({ id, path: `/?share=${id}`, expires });
}

/** GET /api/share/<id>: a shared domain's findings, for anyone with the link until it expires. */
export async function sharedView(id: string, db: D1Database): Promise<Response> {
	const share = await db.prepare("SELECT domain, days, expires_at FROM shares WHERE id = ? AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
		.bind(id).first<{ domain: string; days: number; expires_at: string }>();
	if (!share) return json({ error: `This shared report has expired or doesn't exist. Shared links last ${SHARE_DAYS} days.` }, 404);
	return json({ shared: true, domain: share.domain, days: share.days, expires: share.expires_at, analysis: await domainAnalysis(db, share.domain, share.days) });
}

async function domainRows(url: URL, db: D1Database, domain: string): Promise<Response> {
	const days = periodOf(url.searchParams.get("days"));
	const offset = Math.max(0, Math.min(50_000, Math.floor(Number(url.searchParams.get("offset")) || 0)));
	const { reports } = await domainReports(db, domain, days);
	return json({ domain, days, offset, ...filterRows(domain, reports, rowFilter(url.searchParams), offset, 100) });
}

async function exportDomain(url: URL, db: D1Database, domain: string): Promise<Response> {
	const days = periodOf(url.searchParams.get("days"));
	const { reports } = await domainReports(db, domain, days);
	const { rows } = filterRows(domain, reports, rowFilter(url.searchParams), 0, 50_000);
	return new Response([CSV_HEAD.join(","), ...rows.map(csvRow)].join("\r\n") + "\r\n", { headers: {
		"content-type": "text/csv; charset=utf-8", "cache-control": "no-store",
		"content-disposition": `attachment; filename="dmarc-${domain}-${days}-days.csv"`,
	} });
}

export async function tlsRows(db: D1Database, domain: string, days: number): Promise<TlsRow[]> {
	const { results } = await db.prepare(`SELECT org, end_at, policy_type, success, failure, details FROM tls_reports WHERE domain = ?
		AND COALESCE(end_at, created_at) > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) ORDER BY end_at DESC LIMIT 5000`).bind(domain, `-${days} days`).all<TlsRow>();
	return results;
}

async function tlsView(url: URL, db: D1Database, domain: string, resolve: Resolve): Promise<Response> {
	const days = periodOf(url.searchParams.get("days"));
	const address = await reportAddress(db);
	const [record, rows, daily, where] = await Promise.all([
		currentTlsRecord(domain, resolve).catch(() => null),
		tlsRows(db, domain, days),
		db.prepare(`SELECT substr(COALESCE(end_at, created_at), 1, 10) AS day, SUM(success) AS success, SUM(failure) AS failure FROM tls_reports
			WHERE domain = ? AND COALESCE(end_at, created_at) > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?) GROUP BY day ORDER BY day`).bind(domain, `-${days} days`).all(),
		dnsHost(domain, resolve),
	]);
	const hasUs = address ? tlsRecordHasUs(record, address) : false;
	const name = where.zone === domain ? "_smtp._tls" : `_smtp._tls.${domain.slice(0, -(where.zone.length + 1))}`;
	return json({
		domain, days, address, record, hasUs,
		setup: address && !hasUs ? { type: "TXT", name, value: tlsRecord(record, address), action: record ? "edit" : "add" } : null,
		summary: summariseTls(rows, domain),
		daily: daily.results,
	});
}

async function removeDomain(db: D1Database, domain: string): Promise<Response> {
	await db.batch([
		db.prepare("DELETE FROM report_rows WHERE report IN (SELECT id FROM reports WHERE domain = ? AND source = 'mail')").bind(domain),
		db.prepare("DELETE FROM reports WHERE domain = ? AND source = 'mail'").bind(domain),
		db.prepare("DELETE FROM domains WHERE domain = ?").bind(domain),
		db.prepare("DELETE FROM labels WHERE domain = ?").bind(domain),
		db.prepare("DELETE FROM shares WHERE domain = ?").bind(domain),
		db.prepare("DELETE FROM tls_reports WHERE domain = ?").bind(domain),
	]);
	return json({ ok: true });
}

// --- Uploads ------------------------------------------------------------------------------------------

async function upload(request: Request, db: D1Database, resolve: Resolve): Promise<Response> {
	const size = Number(request.headers.get("content-length") ?? 0);
	if (size > FILES_PER_UPLOAD * MAX_FILE) return json({ error: "That's too much in one go. Upload up to 10 report files of 5 MB each." }, 413);
	let form: FormData;
	try {
		form = await request.formData();
	} catch {
		return json({ error: "Please choose one or more report files to upload." }, 400);
	}
	const files = (form.getAll("file") as unknown as (File | string)[]).filter((f): f is File => typeof f !== "string");
	if (!files.length) return json({ error: "Please choose one or more report files to upload." }, 400);
	if (files.length > FILES_PER_UPLOAD) return json({ error: `Please upload up to ${FILES_PER_UPLOAD} files at a time.` }, 400);
	const uploadId = newId();
	const out: { name: string; ok: boolean; error?: string; domain?: string; org?: string }[] = [];
	for (const file of files) {
		const name = (file.name || "report").slice(0, 120);
		try {
			if (file.size > MAX_FILE) throw new ReportError("This file is too big. Report files can be up to 5 MB.");
			for (const xml of await unpackReport(new Uint8Array(await file.arrayBuffer()))) {
				const report = parseReport(xml);
				await saveReport(db, report.policy.domain, report, "upload", uploadId, resolve);
				out.push({ name, ok: true, domain: report.policy.domain, org: report.org });
			}
		} catch (e) {
			if (!(e instanceof ReportError)) console.error("upload", e);
			out.push({ name, ok: false, error: e instanceof ReportError ? e.message : "This file couldn't be read." });
		}
	}
	if (!out.some((f) => f.ok)) return json({ files: out, error: out.length === 1 ? out[0].error : "None of those files could be read." }, 400);
	return json({ id: uploadId, files: out, ...(await uploadAnalysis(db, uploadId)) });
}

async function uploadAnalysis(db: D1Database, id: string): Promise<{ results: Analysis[] }> {
	const { results } = await db.prepare(`${JOIN} WHERE r.upload_id = ? AND r.source = 'upload' LIMIT 50000`).bind(id).all<JoinedRow>();
	const byDomain = new Map<string, JoinedRow[]>();
	for (const r of results) {
		const d = (JSON.parse(r.policy) as Policy).domain;
		byDomain.set(d, [...(byDomain.get(d) ?? []), r]);
	}
	return { results: [...byDomain].map(([domain, rows]) => analyse(domain, regroup(rows))) };
}

// --- The API ------------------------------------------------------------------------------------------

/** Handles /api/domains*, /api/upload and /api/uploads/* for the signed-in owner. Null for other paths. */
export async function handleReports(request: Request, path: string, db: D1Database, resolve: Resolve): Promise<Response | null> {
	const url = new URL(request.url);
	const m = request.method;
	if (path === "/api/domains" && m === "GET") return listDomains(db);
	if (path === "/api/domains" && m === "POST") return addDomain(request, db);
	if (path === "/api/upload" && m === "POST") return upload(request, db, resolve);
	const up = /^\/api\/uploads\/([a-z0-9]{10})$/.exec(path);
	if (up && m === "GET") {
		const res = await uploadAnalysis(db, up[1]);
		return res.results.length ? json({ id: up[1], ...res }) : json({ error: "That upload isn't there any more. Uploads are kept for 12 months." }, 404);
	}
	if (up && m === "DELETE") {
		await db.batch([
			db.prepare("DELETE FROM report_rows WHERE report IN (SELECT id FROM reports WHERE upload_id = ? AND source = 'upload')").bind(up[1]),
			db.prepare("DELETE FROM reports WHERE upload_id = ? AND source = 'upload'").bind(up[1]),
		]);
		return json({ ok: true });
	}
	const d = /^\/api\/domains\/([^/]+)(\/[a-z]+)?$/.exec(path);
	if (!d) return null;
	const domain = cleanDmarcDomain(decodeURIComponent(d[1]));
	if (!domain || !(await db.prepare("SELECT 1 FROM domains WHERE domain = ?").bind(domain).first())) return json({ error: "That domain isn't in your list." }, 404);
	const what = d[2] ?? "";
	if (m === "GET" && what === "") return domainView(url, db, domain, resolve);
	if (m === "DELETE" && what === "") return removeDomain(db, domain);
	if (m === "POST" && what === "/settings") return domainSettings(request, db, domain);
	if (m === "POST" && what === "/labels") return setLabel(request, db, domain);
	if (m === "POST" && what === "/share") return shareDomain(request, db, domain);
	if (m === "GET" && what === "/rows") return domainRows(url, db, domain);
	if (m === "GET" && what === "/export") return exportDomain(url, db, domain);
	if (m === "GET" && what === "/tls") return tlsView(url, db, domain, resolve);
	return json({ error: "Not found" }, 404);
}
