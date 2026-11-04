// The scheduled job (every 30 minutes): looks at each domain once a day for its DMARC record, the rollout
// reminder, alerts and the weekly summary, then tidies away reports over 12 months old.

import { alertSettings, alertState, dmarcAlerts, rollout, STAGES, weeklyEmail } from "./dmarc-core.ts";
import { summariseTls, tlsAlert } from "./tls-reports-core.ts";
import { NOW, reportAddress, type Env } from "./db.ts";
import { domainAnalysis, KEEP_DAYS, refreshRecord, tlsRows, type DomainRow } from "./reports.ts";
import type { Resolve } from "./dns.ts";
import type { Send } from "./send.ts";
import { brandOf } from "./brand.ts";
import { ALERT_TYPE, sendHooks } from "./hooks.ts";

/** Domains looked at in one run, and how long a run may take. */
const PER_RUN = 15;
const RUN_MS = 20_000;

function reminderEmail(domain: string, r: ReturnType<typeof rollout>, link: string, name: string): { subject: string; text: string } {
	const next = r.steps[r.current + 1];
	return {
		subject: `${domain}: time for the next DMARC step`,
		text: [
			"Hello,",
			`Everything that sends email as ${domain} has passed DMARC for the past two weeks, so it's time for the next step: ${next.title.toLowerCase()}. ${next.what}`,
			`Change the TXT record called _dmarc on ${domain} to:\n\n${next.record}`,
			`Your reports and the full plan: ${link}`,
			`You get this email because reminders are on for this domain in ${name}. You can switch them off in the domain's settings.`,
		].join("\n\n"),
	};
}

/** `origin` is where the app lives (such as https://dmarc.example.com), for links in emails. */
export async function runCron(env: Env, resolve: Resolve, send: Send | null, origin: string | null): Promise<void> {
	const db = env.DB;
	const started = Date.now();
	const address = await reportAddress(db);
	const brand = await brandOf(db);
	// The emails' own wording names the app; a white-label install uses its own name.
	const named = (t: { subject: string; text: string }) => ({ subject: t.subject, text: t.text.replaceAll("DMARC Reports", brand.name) });
	const linkFor = (domain: string) => (origin ? `${origin}/?domain=${encodeURIComponent(domain)}` : "your DMARC Reports app");
	const { results } = await db.prepare(`SELECT * FROM domains WHERE checked_at IS NULL OR checked_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day') ORDER BY checked_at LIMIT ${PER_RUN}`).all<DomainRow>();
	for (const row of results) {
		if (Date.now() - started > RUN_MS) break;
		try {
			const { record, stage, since, seen } = await refreshRecord(db, row, resolve);
			const link = linkFor(row.domain);
			if (address && send && row.reminders && stage >= 0 && stage < STAGES.length - 1 && row.reminded_stage !== stage + 1) {
				const r = rollout({ record, report: address, since, recent: await domainAnalysis(db, row.domain, 14) });
				if (r.ready) {
					const { subject, text } = reminderEmail(row.domain, r, link, brand.name);
					if (await send(subject, text)) await db.prepare("UPDATE domains SET reminded_stage = ? WHERE domain = ?").bind(stage + 1, row.domain).run();
				}
			}
			const on = alertSettings(row.alerts);
			const { due, state } = dmarcAlerts({
				domain: row.domain, recent: await domainAnalysis(db, row.domain, 3), before: await domainAnalysis(db, row.domain, 33, 3),
				state: alertState(row.alert_state), on, link, now: new Date(),
			});
			const tls = on.tls ? tlsAlert(row.domain, summariseTls(await tlsRows(db, row.domain, 3), row.domain), state.tlsAt ?? null, new Date(), link) : null;
			if (tls) {
				due.push({ kind: "tls", ...tls });
				state.tlsAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
			}
			if (send) for (const a of due) await send(named(a).subject, named(a).text);
			for (const a of due) await sendHooks(db, ALERT_TYPE[a.kind], { domain: row.domain, subject: named(a).subject, text: named(a).text, link }, brand.name).catch((e) => console.error("webhook", e));
			await db.prepare("UPDATE domains SET alert_state = ? WHERE domain = ?").bind(JSON.stringify(state), row.domain).run();
			if (send && row.weekly && (!row.summary_at || Date.parse(row.summary_at) < Date.now() - 6.5 * 86_400_000)) {
				const week = await domainAnalysis(db, row.domain, 7);
				const plan = address ? rollout({ record, report: address, since, recent: await domainAnalysis(db, row.domain, 14), seen }) : null;
				const { subject, text } = named(weeklyEmail(row.domain, week, plan, link));
				if (await send(subject, text)) await db.prepare(`UPDATE domains SET summary_at = ${NOW} WHERE domain = ?`).bind(row.domain).run();
			}
		} catch (e) {
			console.error("daily check", row.domain, e);
			await db.prepare(`UPDATE domains SET checked_at = ${NOW} WHERE domain = ?`).bind(row.domain).run().catch(() => undefined);
		}
	}
	await db.batch([
		db.prepare(`DELETE FROM report_rows WHERE report IN (SELECT id FROM reports WHERE created_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-${KEEP_DAYS} days'))`),
		db.prepare(`DELETE FROM reports WHERE created_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-${KEEP_DAYS} days')`),
		db.prepare("DELETE FROM ips WHERE looked_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')"),
		db.prepare(`DELETE FROM tls_reports WHERE created_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-${KEEP_DAYS} days')`),
		db.prepare("DELETE FROM shares WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"),
	]);
}
