// TLS reports, the rules with no database or network. Mail servers that support SMTP TLS Reporting
// (RFC 8460: Google, Microsoft and others) send a daily JSON report to the address in a domain's _smtp._tls
// TXT record, saying how many connections to its mail servers were encrypted and why any weren't. They come
// to the same report address as the DMARC reports (src/mail.ts tells them apart).

/** Reports are kept for 12 months, like DMARC reports. */
export const TLS_KEEP_DAYS = 365;
/** Reports taken in for one domain in a day. Real domains get two to five (Google, Microsoft and a few others). */
export const TLS_REPORTS_PER_DAY = 10;
/** Failure details kept from each report. */
const MAX_DETAILS = 50;

export interface TlsFailure {
	result: string;
	mx: string | null;
	ip: string | null;
	sendingIp: string | null;
	count: number;
}

export interface TlsPolicy {
	/** sts (MTA-STS), tlsa (DANE) or no-policy-found. */
	type: string;
	success: number;
	failure: number;
	failures: TlsFailure[];
}

export interface TlsReport {
	org: string;
	reportId: string;
	begin: string | null;
	end: string | null;
	/** The domain the report is about. */
	domain: string;
	policies: TlsPolicy[];
}

export class TlsReportError extends Error {}

const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const str = (v: unknown, max = 200) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);
const isoOf = (v: unknown) => {
	const t = typeof v === "string" ? Date.parse(v) : NaN;
	return Number.isFinite(t) ? new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z") : null;
};

/** Reads one RFC 8460 report. Throws TlsReportError when it isn't one. */
export function parseTlsReport(text: string): TlsReport {
	let j: Record<string, unknown>;
	try {
		j = JSON.parse(text);
	} catch {
		throw new TlsReportError("That isn't a TLS report (it isn't JSON).");
	}
	if (!j || typeof j !== "object" || !Array.isArray(j.policies)) throw new TlsReportError("That isn't a TLS report.");
	const range = (j["date-range"] ?? {}) as Record<string, unknown>;
	const policies: TlsPolicy[] = [];
	let domain = "";
	for (const p of (j.policies as Record<string, unknown>[]).slice(0, 20)) {
		const pol = (p?.policy ?? {}) as Record<string, unknown>;
		const sum = (p?.summary ?? {}) as Record<string, unknown>;
		domain ||= (str(pol["policy-domain"]) ?? "").toLowerCase().replace(/\.$/, "");
		const details = Array.isArray(p?.["failure-details"]) ? (p["failure-details"] as Record<string, unknown>[]) : [];
		policies.push({
			type: str(pol["policy-type"], 40) ?? "no-policy-found",
			success: num(sum["total-successful-session-count"]),
			failure: num(sum["total-failure-session-count"]),
			failures: details.slice(0, MAX_DETAILS).map((d) => ({
				result: str(d["result-type"], 60) ?? "unknown",
				mx: str(d["receiving-mx-hostname"])?.toLowerCase().replace(/\.$/, "") ?? null,
				ip: str(d["receiving-ip"], 60),
				sendingIp: str(d["sending-mta-ip"], 60),
				count: num(d["failed-session-count"]),
			})),
		});
	}
	if (!domain) throw new TlsReportError("That TLS report doesn't say which domain it's about.");
	return {
		org: str(j["organization-name"]) ?? "Unknown",
		reportId: str(j["report-id"]) ?? `${str(j["organization-name"]) ?? "x"}-${isoOf(range["start-datetime"]) ?? ""}`,
		begin: isoOf(range["start-datetime"]),
		end: isoOf(range["end-datetime"]),
		domain,
		policies,
	};
}

/** Opens an attachment: plain JSON, or gzipped (.json.gz, the usual). */
export async function unpackTls(bytes: Uint8Array): Promise<string> {
	if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
		const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
		const reader = stream.getReader();
		const parts: Uint8Array[] = [];
		let size = 0;
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > 5 * 1024 * 1024) { await reader.cancel(); throw new TlsReportError("That TLS report is too big."); }
			parts.push(value);
		}
		const all = new Uint8Array(size);
		let at = 0;
		for (const p of parts) { all.set(p, at); at += p.byteLength; }
		return new TextDecoder().decode(all);
	}
	return new TextDecoder().decode(bytes);
}

/** What each failure means, in plain English, and what to do. */
export const RESULTS: Record<string, [string, string]> = {
	"starttls-not-supported": ["Your mail server didn't offer encryption", "Turn on STARTTLS on the server that receives your email, or ask your email provider."],
	"certificate-host-mismatch": ["The certificate doesn't match the mail server's name", "The certificate on your mail server must cover the name in your MX record."],
	"certificate-expired": ["Your mail server's certificate has expired", "Renew the certificate on the server that receives your email."],
	"certificate-not-trusted": ["Your mail server's certificate isn't trusted", "Use a certificate from a public authority (such as Let's Encrypt), with its full chain."],
	"validation-failure": ["The secure connection couldn't be checked", "Look at your mail server's certificate and encryption settings."],
	"tlsa-invalid": ["Your DANE (TLSA) record is wrong", "Update the TLSA record to match your mail server's current certificate."],
	"dnssec-invalid": ["DNSSEC failed for your domain", "Your DNS host's DNSSEC signatures didn't check out. Ask your DNS host."],
	"dane-required": ["DANE was required but missing", "Add the TLSA records for your mail servers, or stop requiring DANE."],
	"sts-policy-fetch-error": ["Your MTA-STS policy file couldn't be fetched", "Check https://mta-sts.<your domain>/.well-known/mta-sts.txt loads, with a valid certificate."],
	"sts-policy-invalid": ["Your MTA-STS policy file has a mistake", "Check the policy file's lines (version, mode, mx and max_age)."],
	"sts-webpki-invalid": ["The MTA-STS website's certificate isn't valid", "Fix the certificate on mta-sts.<your domain>."],
};

export interface TlsRow {
	org: string;
	end_at: string | null;
	policy_type: string;
	success: number;
	failure: number;
	details: string | null;
}

export interface TlsSummary {
	reports: number;
	success: number;
	failure: number;
	/** Whole percentages of connections that were encrypted, rounded down. */
	rate: number;
	policy: string | null;
	reporters: { org: string; sessions: number }[];
	problems: { result: string; title: string; fix: string; count: number; mx: string[] }[];
	from: string | null;
	to: string | null;
}

/** Sums up a period's reports. */
export function summariseTls(rows: TlsRow[], domain: string): TlsSummary {
	const byOrg = new Map<string, number>();
	const byResult = new Map<string, { count: number; mx: Set<string> }>();
	let success = 0, failure = 0;
	const types = new Map<string, number>();
	let from: string | null = null, to: string | null = null;
	for (const r of rows) {
		success += r.success;
		failure += r.failure;
		byOrg.set(r.org, (byOrg.get(r.org) ?? 0) + r.success + r.failure);
		types.set(r.policy_type, (types.get(r.policy_type) ?? 0) + r.success + r.failure);
		if (r.end_at) { if (!from || r.end_at < from) from = r.end_at; if (!to || r.end_at > to) to = r.end_at; }
		let details: TlsFailure[] = [];
		try { details = r.details ? JSON.parse(r.details) : []; } catch { /* none */ }
		for (const d of details) {
			const x = byResult.get(d.result) ?? { count: 0, mx: new Set<string>() };
			x.count += d.count;
			if (d.mx) x.mx.add(d.mx);
			byResult.set(d.result, x);
		}
	}
	const all = success + failure;
	const policy = [...types].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
	return {
		reports: rows.length, success, failure, rate: all ? Math.floor((success / all) * 100) : 0, policy,
		reporters: [...byOrg].sort((a, b) => b[1] - a[1]).map(([org, sessions]) => ({ org, sessions })),
		problems: [...byResult].sort((a, b) => b[1].count - a[1].count).map(([result, x]) => {
			const [title, fix] = RESULTS[result] ?? [`Failed: ${result}`, "Look at your mail server's encryption settings."];
			return { result, title, fix: fix.replace(/<your domain>/g, domain), count: x.count, mx: [...x.mx].slice(0, 5) };
		}),
		from, to,
	};
}

/** The _smtp._tls record to add or change: theirs with our address added, or a new one. */
export function tlsRecord(current: string | null, address: string): string {
	const ours = `mailto:${address}`;
	if (!current || !/^v=TLSRPTv1/i.test(current.trim())) return `v=TLSRPTv1; rua=${ours}`;
	const m = /rua=([^;]*)/i.exec(current);
	if (!m) return `${current.trim().replace(/;?\s*$/, "")}; rua=${ours}`;
	const list = m[1].split(",").map((s) => s.trim()).filter(Boolean);
	if (list.some((s) => s.toLowerCase() === ours.toLowerCase())) return current.trim();
	return current.replace(m[0], `rua=${[...list, ours].join(",")}`).trim();
}

/** Whether a record already sends reports to us. */
export function tlsRecordHasUs(current: string | null, address: string): boolean {
	return !!current && current.toLowerCase().includes(`mailto:${address.toLowerCase()}`);
}

/**
 * The "encryption failing" alert: some connections in the last 3 days weren't encrypted (at least 3, and 1%
 * of them), said at most once a week. Null when there's nothing to say.
 */
export function tlsAlert(domain: string, s: TlsSummary, lastAt: string | null, now: Date, link: string): { subject: string; text: string } | null {
	const all = s.success + s.failure;
	if (s.failure < 3 || s.failure / all < 0.01) return null;
	if (lastAt && now.getTime() - Date.parse(lastAt) < 7 * 86_400_000) return null;
	const lines = s.problems.slice(0, 3).map((p) => `- ${p.title}${p.mx.length ? ` (${p.mx.join(", ")})` : ""}: ${p.count.toLocaleString("en-GB")} times. ${p.fix}`);
	return {
		subject: `${domain}: some email to you wasn't sent encrypted`,
		text: [
			"Hello,",
			`Mail servers reported that ${s.failure.toLocaleString("en-GB")} of ${all.toLocaleString("en-GB")} connections to ${domain}'s mail servers in the last 3 days couldn't be encrypted.`,
			...(lines.length ? [lines.join("\n")] : []),
			s.policy === "sts" ? "Your MTA-STS policy is set, so senders that follow it may have held the mail back rather than send it unencrypted." : "",
			`See everything: ${link}`,
			`You get this email because this alert is on for ${domain} in DMARC Reports. You can switch it off in the domain's settings.`,
		].filter(Boolean).join("\n\n"),
	};
}
