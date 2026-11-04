// Taking in reports by email. Your report address (such as dmarc-reports@example.com) is routed to this
// Worker by Cloudflare Email Routing. Each email's attachments are read: DMARC reports are XML (usually
// zipped or gzipped), TLS reports are JSON (usually gzipped). A report only counts when it's about one of
// your domains (or a subdomain of one); anything else is dropped. Nothing is ever bounced or replied to.

import { brandOf } from "./brand.ts";
import { sendHooks } from "./hooks.ts";
import PostalMime from "postal-mime";
import { MAX_FILE, parseReport, ReportError, unpackReport } from "./dmarc-core.ts";
import { parseTlsReport, TLS_REPORTS_PER_DAY, TlsReportError, unpackTls, type TlsReport } from "./tls-reports-core.ts";
import { newId, setSetting, isoNow } from "./db.ts";
import { saveReport } from "./reports.ts";
import type { Resolve } from "./dns.ts";

/** DMARC reports taken in for one domain in a day, whoever sends them. Real domains get a handful. */
export const MAIL_REPORTS_PER_DAY = 200;
/** Attachments read from one email. Real report emails have one. */
const ATTACHMENTS = 5;

/** Which of your domains a report is about: the domain itself or the closest one above it. */
export function ownerDomain(reportDomain: string, domains: string[]): string | null {
	const d = reportDomain.toLowerCase().replace(/\.$/, "");
	return domains.filter((x) => d === x || d.endsWith(`.${x}`)).sort((a, b) => b.length - a.length)[0] ?? null;
}

const countToday = (db: D1Database, table: "reports" | "tls_reports", domain: string) =>
	db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE domain = ? ${table === "reports" ? "AND source = 'mail'" : ""} AND created_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day')`)
		.bind(domain).first<{ n: number }>().then((r) => r?.n ?? 0);

async function saveTls(db: D1Database, domain: string, r: TlsReport): Promise<boolean> {
	const success = r.policies.reduce((n, p) => n + p.success, 0);
	const failure = r.policies.reduce((n, p) => n + p.failure, 0);
	const type = r.policies.find((p) => p.type !== "no-policy-found")?.type ?? r.policies[0]?.type ?? "no-policy-found";
	const details = r.policies.flatMap((p) => p.failures).slice(0, 50);
	const done = await db.prepare(`INSERT OR IGNORE INTO tls_reports (id, domain, org, report_id, begin_at, end_at, policy_type, success, failure, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(newId(16), domain, r.org, r.reportId, r.begin, r.end, type, success, failure, details.length ? JSON.stringify(details) : null).run();
	return !!done.meta.changes;
}

/** Reads one email and keeps the reports in it. Returns how many DMARC and TLS reports were saved. */
export async function takeMail(db: D1Database, raw: ArrayBuffer | Uint8Array, resolve: Resolve): Promise<{ dmarc: number; tls: number }> {
	const saved = { dmarc: 0, tls: 0 };
	// Each report saved, for webhooks (report.received). Sent once the email is done.
	const events: Record<string, unknown>[] = [];
	if (raw.byteLength > MAX_FILE * 1.4) return saved;
	let mail;
	try {
		mail = await PostalMime.parse(raw, { attachmentEncoding: "arraybuffer" });
	} catch {
		return saved;
	}
	const { results } = await db.prepare("SELECT domain FROM domains").all<{ domain: string }>();
	const domains = results.map((r) => r.domain);
	if (!domains.length) return saved;
	const left = new Map<string, number>();
	const room = async (table: "reports" | "tls_reports", domain: string, max: number) => {
		const key = `${table}|${domain}`;
		if (!left.has(key)) left.set(key, max - (await countToday(db, table, domain)));
		const n = left.get(key)!;
		left.set(key, n - 1);
		return n > 0;
	};

	for (const a of (mail.attachments ?? []).slice(0, ATTACHMENTS)) {
		const bytes = new Uint8Array(a.content as ArrayBuffer);
		if (bytes.byteLength > MAX_FILE) continue;
		// A DMARC report first; if it isn't one, a TLS report.
		let xmls: string[] | null = null;
		try {
			xmls = await unpackReport(bytes);
		} catch (e) {
			if (!(e instanceof ReportError)) console.error("report email", e);
		}
		let dmarcDone = false;
		for (const xml of xmls ?? []) {
			try {
				const report = parseReport(xml);
				dmarcDone = true;
				const domain = ownerDomain(report.policy.domain, domains);
				if (!domain || !(await room("reports", domain, MAIL_REPORTS_PER_DAY))) continue;
				if (await saveReport(db, domain, report, "mail", null, resolve)) {
					saved.dmarc++;
					const messages = report.rows.reduce((n, r) => n + r.count, 0);
					const passed = report.rows.reduce((n, r) => n + (r.dkim === "pass" || r.spf === "pass" ? r.count : 0), 0);
					events.push({ kind: "dmarc", domain, org: report.org, reportId: report.reportId, begin: report.begin || null, end: report.end || null, messages, passed });
				}
			} catch (e) {
				if (!(e instanceof ReportError)) console.error("dmarc report", e);
			}
		}
		if (dmarcDone) continue;
		try {
			const report = parseTlsReport(await unpackTls(bytes));
			const domain = ownerDomain(report.domain, domains);
			if (!domain || !(await room("tls_reports", domain, TLS_REPORTS_PER_DAY))) continue;
			if (await saveTls(db, domain, report)) {
				saved.tls++;
				events.push({ kind: "tls", domain, org: report.org, reportId: report.reportId, begin: report.begin, end: report.end,
					success: report.policies.reduce((n, p) => n + p.success, 0), failure: report.policies.reduce((n, p) => n + p.failure, 0) });
			}
		} catch (e) {
			if (!(e instanceof TlsReportError)) console.error("tls report", e);
		}
	}
	if (saved.dmarc || saved.tls) await setSetting(db, "last_report_at", isoNow());
	if (events.length) {
		const app = (await brandOf(db)).name;
		for (const e of events) await sendHooks(db, "report.received", e, app).catch((err) => console.error("webhook", err));
	}
	return saved;
}
