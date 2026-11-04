// DMARC report reader: run with `node --experimental-strip-types --test test/dmarc.test.ts`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync, deflateRawSync } from "node:zlib";
import {
	alertSettings, alertState, analyse, byDay, csvField, csvRow, filterRows, rowFilter, weeklyEmail, dmarcAlerts, dmarcRecord, parseDmarc, parseReport, parseXml, ptrName, ReportError, rollout, senderFor, stageOf, unpackReport,
	type StoredRow,
} from "../src/dmarc-core.ts";

const GOOGLE = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1760659200</begin><end>1760745599</end></date_range>
  </report_metadata>
  <policy_published><domain>example.co.uk</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>12</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><dkim><domain>example.co.uk</domain><selector>google</selector><result>pass</result></dkim><spf><domain>example.co.uk</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>198.2.180.10</source_ip><count>40</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><dkim><domain>mcsv.net</domain><selector>k2</selector><result>pass</result></dkim><spf><domain>mail198.atl221.mcsv.net</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.9</source_ip><count>3</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><spf><domain>example.co.uk</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`;

function zip(name: string, data: Uint8Array): Uint8Array {
	const packed = deflateRawSync(data);
	const nameB = new TextEncoder().encode(name);
	const local = Buffer.alloc(30);
	local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(8, 8); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameB.length, 26);
	const central = Buffer.alloc(46);
	central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(8, 10); central.writeUInt32LE(packed.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(nameB.length, 28); central.writeUInt32LE(0, 42);
	const cdAt = 30 + nameB.length + packed.length;
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(46 + nameB.length, 12); end.writeUInt32LE(cdAt, 16);
	return new Uint8Array(Buffer.concat([local, nameB, packed, central, nameB, end]));
}

const enc = (s: string) => new TextEncoder().encode(s);

test("reports open as plain XML, .xml.gz and .zip", async () => {
	assert.equal((await unpackReport(enc(GOOGLE)))[0], GOOGLE);
	assert.equal((await unpackReport(new Uint8Array(gzipSync(GOOGLE))))[0], GOOGLE);
	assert.equal((await unpackReport(zip("google.com!example.co.uk!1!2.xml", enc(GOOGLE))))[0], GOOGLE);
});

test("anything that isn't a report is turned away with a reason", async () => {
	await assert.rejects(unpackReport(enc("<html><body>Hello</body></html>")), /doesn't look like a DMARC report/);
	await assert.rejects(unpackReport(new Uint8Array(6 * 1024 * 1024)), /too big/);
	await assert.rejects(unpackReport(new Uint8Array([0x1f, 0x8b, 1, 2, 3])), ReportError);
});

test("a zip bomb stops at the unzipped size cap", async () => {
	const big = new Uint8Array(21 * 1024 * 1024);
	const bomb = new Uint8Array(gzipSync(big));
	assert.ok(bomb.length < 100_000);
	await assert.rejects(unpackReport(bomb), /too big once unzipped/);
});

test("the XML reader refuses DOCTYPE and entities, so nothing outside the file is ever read", () => {
	assert.throws(() => parseXml(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><feedback>&e;</feedback>`), /DOCTYPE/);
	assert.throws(() => parseXml("<feedback><a></b></feedback>"), /damaged/);
	assert.throws(() => parseXml("<feedback><a>"), /cut short/);
	const n = parseXml("<feedback><org_name>A &amp; B &#x41;</org_name><x/></feedback>");
	assert.equal(n.kids[0].kids[0].text, "A & B A");
});

test("a Google report is read row by row", () => {
	const r = parseReport(GOOGLE);
	assert.equal(r.org, "google.com");
	assert.equal(r.reportId, "1234567890");
	assert.equal(r.begin, "2025-10-17T00:00:00Z");
	assert.deepEqual(r.policy, { domain: "example.co.uk", p: "none", sp: "none", pct: 100, adkim: "r", aspf: "r" });
	assert.equal(r.rows.length, 3);
	assert.deepEqual(r.rows[1].dkimAuth, [{ domain: "mcsv.net", selector: "k2", result: "pass" }]);
	assert.equal(r.rows[1].dkim, "fail");
	assert.throws(() => parseReport("<feedback><x/></feedback>"), /doesn't look like a DMARC report/);
});

test("senders are named from DKIM, SPF and reverse DNS, never from your own domain", () => {
	const r = parseReport(GOOGLE);
	assert.equal(senderFor(r.rows[0], "example.co.uk", "mail-sor-f41.google.com").name, "Google Workspace / Gmail");
	assert.equal(senderFor(r.rows[1], "example.co.uk").id, "mailchimp");
	assert.deepEqual(senderFor(r.rows[2], "example.co.uk"), { id: "other", name: "A server we don't recognise", known: false });
	assert.equal(senderFor(r.rows[2], "example.co.uk", "host9.badhost.co.uk").name, "A server at badhost.co.uk");
	assert.equal(senderFor({ ip: "1.2.3.4", dkimAuth: [], spfAuth: { domain: "eu-west-1.amazonses.com", result: "pass" } }, "example.co.uk").id, "ses");
});

test("reverse DNS names for IPv4 and IPv6", () => {
	assert.equal(ptrName("209.85.220.41"), "41.220.85.209.in-addr.arpa");
	assert.equal(ptrName("2a00:1450:4864:20::131"), "1.3.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.4.6.8.4.0.5.4.1.0.0.a.2.ip6.arpa");
	assert.equal(ptrName("999.1.1.1"), null);
	assert.equal(ptrName("hello"), null);
});

function stored(xml: string, ptrs: Record<string, string> = {}) {
	const r = parseReport(xml);
	return { ...r, rows: r.rows.map((row): StoredRow => ({ ...row, ptr: ptrs[row.ip] ?? null, sender: senderFor(row, r.policy.domain, ptrs[row.ip]) })) };
}

test("the analysis says what to fix, sender by sender", () => {
	const a = analyse("example.co.uk", [stored(GOOGLE, { "209.85.220.41": "mail-sor-f41.google.com" })]);
	assert.equal(a.messages, 55);
	assert.equal(a.passed, 12);
	assert.equal(a.passRate, 21);
	assert.equal(a.headline, "1 sender to fix");
	// The server that isn't yours doesn't count against your own mail.
	const notYours = a.senders.filter((s) => s.status === "info").reduce((n, s) => n + s.messages, 0);
	assert.ok(notYours > 0);
	assert.equal(a.others, notYours);
	assert.equal(a.own.messages, 55 - notYours);
	assert.equal(a.own.passed, 12);
	const [mailchimp, unknown, google] = a.senders;
	assert.equal(mailchimp.name, "Mailchimp");
	assert.equal(mailchimp.status, "fail");
	assert.match(mailchimp.summary, /signs with its own name \(mcsv\.net\)/);
	assert.match(mailchimp.fix!.steps.join(" "), /Account & billing › Domains/);
	assert.equal(unknown.status, "info");
	assert.match(unknown.summary, /one of your own services/);
	assert.match(unknown.summary, /mark it Not mine/);
	assert.equal(google.status, "pass");
	assert.equal(a.policy?.p, "none");
});

test("DMARC records keep other tags and report addresses and add ours", () => {
	const current = "v=DMARC1; p=none; rua=mailto:dmarc@other.com; ruf=mailto:f@x.com; fo=1";
	assert.equal(dmarcRecord(current, "dmarc-reports@example.net", "quarantine", 25),
		"v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@other.com,mailto:dmarc-reports@example.net; ruf=mailto:f@x.com; fo=1");
	assert.equal(dmarcRecord(null, "dmarc-reports@example.net", "none"), "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.net");
	assert.equal(parseDmarc('"v=DMARC1; p=reject" "; pct=50"').get("pct"), "50");
	assert.equal(stageOf("quarantine", 50), 2);
	assert.equal(stageOf("reject", 100), 4);
	assert.equal(stageOf(undefined, undefined), 0);
});

test("the rollout waits for time and for every real sender to pass", () => {
	const now = new Date("2026-11-20T09:00:00Z");
	const bad = analyse("example.co.uk", [stored(GOOGLE)]);
	const early = rollout({ record: "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.net", report: "dmarc-reports@example.net", since: "2026-11-01T00:00:00Z", recent: bad, now });
	assert.equal(early.current, 0);
	assert.equal(early.ready, false);
	assert.match(early.waitingFor.join(" "), /29 November/);
	assert.match(early.waitingFor.join(" "), /Mailchimp is still failing/);
	assert.equal(early.steps[1].date, "2026-11-29T00:00:00Z");
	assert.equal(early.steps[4].date, "2027-01-10T00:00:00Z");
	assert.equal(early.nextRecord, "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@example.net");

	const good = analyse("example.co.uk", [stored(GOOGLE.replace(/<record>\s*<row><source_ip>198[\s\S]*?<\/record>/, ""), { "209.85.220.41": "mail-sor-f41.google.com" })]);
	const later = rollout({ record: "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.net", report: "dmarc-reports@example.net", since: "2026-10-01T00:00:00Z", recent: good, now });
	assert.equal(later.ready, true, later.waitingFor.join("; "));
	assert.deepEqual(later.steps.map((s) => s.state), ["now", "next", "later", "later", "later"]);

	const none = rollout({ record: null, report: "dmarc-reports@example.net", since: null, recent: good, now });
	assert.equal(none.current, -1);
	assert.equal(none.steps[0].state, "next");
	assert.equal(none.ready, false);
});

const FORWARDS = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>Enterprise Outlook</org_name><report_id>fw1</report_id><date_range><begin>1760659200</begin><end>1760745599</end></date_range></report_metadata>
  <policy_published><domain>example.co.uk</domain><p>reject</p><pct>100</pct></policy_published>
  <record>
    <row><source_ip>209.85.218.1</source_ip><count>9</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><dkim><domain>example.co.uk</domain><selector>google</selector><result>fail</result></dkim><spf><domain>forwarder.example</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>40.107.1.1</source_ip><count>4</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf><reason><type>mailing_list</type></reason></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><spf><domain>lists.example.org</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>54.240.1.1</source_ip><count>6</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><dkim><domain>atlassian.net</domain><selector>s1</selector><result>pass</result></dkim><spf><domain>bounces.amazonses.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>198.51.100.7</source_ip><count>2</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.co.uk</header_from></identifiers>
    <auth_results><spf><domain>example.co.uk</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`;

test("forwarded mail gets its own calm label and doesn't count against you", () => {
	const r = parseReport(FORWARDS);
	assert.deepEqual(r.rows[1].reasons, ["mailing_list"]);
	const a = analyse("example.co.uk", [stored(FORWARDS)]);
	const fwd = a.senders.find((s) => s.key === "forwarded")!;
	assert.equal(fwd.messages, 13);
	assert.equal(fwd.status, "info");
	assert.match(fwd.summary, /forwarding rule or a mailing list/);
	assert.equal(a.forwarded, 13);
	assert.equal(a.own.messages + a.others + a.forwarded, a.messages);
});

test("an app on someone else's servers is named with \"via\", and SPF says whose domain it checked", () => {
	const r = parseReport(FORWARDS);
	assert.deepEqual(senderFor(r.rows[2], "example.co.uk"), { id: "atlassian", name: "Atlassian (Jira, Confluence) via Amazon SES", known: true });
	const a = analyse("example.co.uk", [stored(FORWARDS)]);
	const atl = a.senders.find((s) => s.id === "atlassian")!;
	assert.deepEqual(atl.spfDomains, [{ domain: "bounces.amazonses.com", yours: false }]);
	assert.ok(atl.found.some((l) => /your SPF record doesn't apply/.test(l)));
});

test("Mine and Not mine change the verdict and the rollout", () => {
	const key = "other:A server we don't recognise";
	const plain = analyse("example.co.uk", [stored(FORWARDS)]);
	assert.equal(plain.senders.find((s) => s.key === key)!.status, "info");
	const mine = analyse("example.co.uk", [stored(FORWARDS)], new Map([[key, "mine"]]));
	const s = mine.senders.find((x) => x.key === key)!;
	assert.equal(s.label, "mine");
	assert.equal(s.status, "fail");
	const now = new Date("2026-12-01T00:00:00Z");
	const r = rollout({ record: "v=DMARC1; p=none; rua=mailto:a@b.c", report: "a@b.c", since: "2026-10-01T00:00:00Z", recent: mine, now });
	assert.ok(r.waitingFor.some((w) => w.startsWith("A server we don't recognise is still failing")));
	const atlNot = analyse("example.co.uk", [stored(FORWARDS)], new Map([["atlassian", "not"]]));
	assert.equal(atlNot.senders.find((x) => x.id === "atlassian")!.status, "info");
});

test("steps a domain went straight past show as skipped", () => {
	const recent = analyse("example.co.uk", [stored(GOOGLE)]);
	const r = rollout({ record: "v=DMARC1; p=reject; rua=mailto:a@b.c", report: "a@b.c", since: "2026-10-20T00:00:00Z", recent, seen: [0, 4] });
	assert.deepEqual(r.steps.map((s) => s.state), ["done", "skipped", "skipped", "skipped", "now"]);
});

test("alerts: a new sender, your mail failing and reports stopping are each said once", () => {
	const on = alertSettings(null);
	assert.deepEqual(on, { new: true, failing: true, silent: true, tls: true, mineOnly: false });
	assert.deepEqual(alertSettings('{"new":false,"mineOnly":true}'), { new: false, failing: true, silent: true, tls: true, mineOnly: true });
	assert.deepEqual(alertSettings('{"new":false,"tls":false}'), { new: false, failing: true, silent: true, tls: false, mineOnly: false });
	const google = analyse("example.co.uk", [stored(GOOGLE)]);
	const empty = analyse("example.co.uk", []);
	const now = new Date("2026-11-01T09:00:00Z");
	const base = { domain: "example.co.uk", on, link: "https://dmarc.example.net/?domain=example.co.uk", now };
	// First run: everything seen so far is just remembered.
	const first = dmarcAlerts({ ...base, recent: google, before: google, state: alertState(null) });
	assert.equal(first.due.filter((d) => d.kind === "new").length, 0);
	// Mailchimp is failing (40 emails, none passed) and yours, so that's said, then not again for a week.
	assert.deepEqual(first.due.map((d) => d.kind), ["failing"]);
	assert.match(first.due[0].subject, /Mailchimp is failing DMARC|email from Mailchimp is failing DMARC/);
	// Mine only: Mailchimp isn't marked Mine, so nothing is said until it is.
	const mineOnly = { ...on, mineOnly: true };
	assert.deepEqual(dmarcAlerts({ ...base, on: mineOnly, recent: google, before: google, state: alertState(null) }).due, []);
	const marked = analyse("example.co.uk", [stored(GOOGLE)], new Map([["mailchimp", "mine"]]));
	assert.deepEqual(dmarcAlerts({ ...base, on: mineOnly, recent: marked, before: marked, state: alertState(null) }).due.map((d) => d.kind), ["failing"]);
	const again = dmarcAlerts({ ...base, recent: google, before: google, state: first.state });
	assert.deepEqual(again.due, []);
	// A sender never seen before turns up.
	const fwd = analyse("example.co.uk", [stored(FORWARDS)]);
	const fresh = dmarcAlerts({ ...base, recent: fwd, before: google, state: again.state });
	const news = fresh.due.find((d) => d.kind === "new")!;
	assert.match(news.text, /Atlassian/);
	assert.doesNotMatch(news.text, /Forwarded mail/);
	// Reports stop: said once, and again only after they've come back and stopped again.
	const quiet = dmarcAlerts({ ...base, recent: empty, before: google, state: fresh.state });
	assert.deepEqual(quiet.due.map((d) => d.kind), ["silent"]);
	assert.deepEqual(dmarcAlerts({ ...base, recent: empty, before: google, state: quiet.state }).due, []);
	// Switched off: nothing is sent, but the state still moves on.
	const off = dmarcAlerts({ ...base, on: { new: false, failing: false, silent: false, tls: false }, recent: empty, before: google, state: fresh.state });
	assert.deepEqual(off.due, []);
	assert.ok(off.state.silentAt);
});

test("CSV export quotes what it must and never starts a cell with a formula", () => {
	assert.equal(csvField("plain"), "plain");
	assert.equal(csvField('say "hi", there'), '"say ""hi"", there"');
	assert.equal(csvField("=HYPERLINK(1)"), "'=HYPERLINK(1)");
	assert.equal(csvField(null), "");
	const r = parseReport(GOOGLE).rows[1];
	const line = csvRow({ end: "2026-10-17T23:59:59Z", org: "google.com", ptr: null, sender: "Mailchimp", ...r });
	assert.equal(line, "2026-10-17,google.com,198.2.180.10,,Mailchimp,40,fail,fail,fail,none,example.co.uk,mcsv.net (k2): pass,mail198.atl221.mcsv.net: pass");
});

test("the weekly email leads with your own mail and what to fix", () => {
	const a = analyse("example.co.uk", [stored(GOOGLE)]);
	const r = rollout({ record: "v=DMARC1; p=none; rua=mailto:a@b.c", report: "a@b.c", since: "2026-10-01T00:00:00Z", recent: a, now: new Date("2026-11-01T00:00:00Z") });
	const w = weeklyEmail("example.co.uk", a, r, "https://dmarc.example.net/?domain=example.co.uk");
	assert.match(w.subject, /^example\.co\.uk: \d+% of your mail passed this week, 1 sender to fix$/);
	assert.match(w.text, /To fix:\n- Mailchimp:/);
	assert.match(w.text, /DMARC enforcement level: Level 1 of 5, Policy: None \(monitor only\)\./);
	assert.match(w.text, /\?domain=example\.co\.uk/);
	const none = weeklyEmail("example.co.uk", analyse("example.co.uk", []), null, "x");
	assert.equal(none.subject, "example.co.uk: no DMARC reports this week");
});

test("mail from subdomains is counted on its own", () => {
	const xml = GOOGLE.replace("<header_from>example.co.uk</header_from></identifiers>\n    <auth_results><dkim><domain>mcsv.net</domain>", "<header_from>news.example.co.uk</header_from></identifiers>\n    <auth_results><dkim><domain>mcsv.net</domain>");
	const a = analyse("example.co.uk", [stored(xml)]);
	assert.deepEqual(a.subdomains, [{ domain: "news.example.co.uk", messages: 40, passed: 0 }]);
	assert.deepEqual(analyse("example.co.uk", [stored(GOOGLE)]).subdomains, []);
});

test("each sender's emails are counted per day for the chart", () => {
	const r = stored(FORWARDS);
	const days = byDay("example.co.uk", [r]);
	assert.ok(days.every((d) => d.day === r.end.slice(0, 10)));
	assert.deepEqual(days.find((d) => d.key === "forwarded"), { day: r.end.slice(0, 10), key: "forwarded", messages: 13, passed: 0 });
	assert.equal(days.reduce((n, d) => n + d.messages, 0), 21);
});

test("every row, filtered by result, sender, provider, selector and what happened", () => {
	const reports = [{ ...stored(GOOGLE), end: "2026-10-20T00:00:00Z" }, { ...stored(FORWARDS), end: "2026-10-21T00:00:00Z" }];
	const all = filterRows("example.co.uk", reports, {});
	assert.equal(all.matched, reports.reduce((n, r) => n + r.rows.length, 0));
	// Newest report first, busiest row first within it.
	assert.equal(all.rows[0].end, "2026-10-21T00:00:00Z");
	assert.ok(all.options.selectors.some((x) => x.name === "google"));
	assert.equal(all.options.orgs[0].messages >= all.options.orgs[all.options.orgs.length - 1].messages, true);
	const failed = filterRows("example.co.uk", reports, { result: "fail" });
	assert.ok(failed.rows.length && failed.rows.every((r) => r.result === "fail"));
	assert.equal(failed.passed, 0);
	const google = filterRows("example.co.uk", reports, { selector: "google" });
	assert.ok(google.rows.some((r) => r.ip === "209.85.220.41") && google.rows.every((r) => r.dkimAuth.some((d) => d.selector === "google")));
	assert.ok(google.rows.length < all.rows.length);
	const mc = filterRows("example.co.uk", reports, { sender: all.options.senders.find((x) => x.name === "Mailchimp")!.key });
	assert.deepEqual(mc.rows.map((r) => r.count), [40]);
	assert.ok(filterRows("example.co.uk", reports, { disposition: "reject" }).rows.every((r) => r.disposition === "reject"));
	assert.equal(filterRows("example.co.uk", reports, { org: "nobody.example" }).matched, 0);
	assert.equal(filterRows("example.co.uk", reports, {}, 1, 1).rows.length, 1);
	// The query string: only what's expected is kept.
	assert.deepEqual(rowFilter(new URLSearchParams("result=fail&sender=mailchimp&org=&selector=s1&disposition=QUARANTINE&x=1")), { result: "fail", sender: "mailchimp", selector: "s1", disposition: "quarantine" });
	assert.deepEqual(rowFilter(new URLSearchParams("result=maybe&disposition=bin")), {});
});
