// Run with `node --experimental-strip-types --test test/tls-reports.test.ts`.
// TLS reports: reading them, the record to add, the summary, the alert, and taking them in by email.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { fakeD1 } from "./fake-d1.ts";
import { parseTlsReport, summariseTls, tlsAlert, tlsRecord, tlsRecordHasUs, TlsReportError, unpackTls } from "../src/tls-reports-core.ts";
import { takeMail } from "../src/mail.ts";
import { tlsRows } from "../src/reports.ts";

const resolve = async () => ({ status: 3, data: [] });

const end = new Date(Date.now() - 3_600_000).toISOString();
const GOOGLE = JSON.stringify({
	"organization-name": "Google Inc.",
	"date-range": { "start-datetime": "2026-10-24T00:00:00Z", "end-datetime": end },
	"contact-info": "smtp-tls-reporting@google.com",
	"report-id": "2026-10-24T00:00:00Z_example.co.uk",
	policies: [{
		policy: { "policy-type": "sts", "policy-string": ["version: STSv1", "mode: enforce"], "policy-domain": "example.co.uk", "mx-host": ["mx.example.co.uk"] },
		summary: { "total-successful-session-count": 970, "total-failure-session-count": 30 },
		"failure-details": [{ "result-type": "certificate-expired", "sending-mta-ip": "209.85.220.41", "receiving-mx-hostname": "mx.example.co.uk.", "receiving-ip": "203.0.113.5", "failed-session-count": 30 }],
	}],
});

test("a TLS report is read, plain or gzipped", async () => {
	const r = parseTlsReport(await unpackTls(gzipSync(GOOGLE)));
	assert.equal(r.org, "Google Inc.");
	assert.equal(r.domain, "example.co.uk");
	assert.deepEqual(r.policies[0], { type: "sts", success: 970, failure: 30, failures: [{ result: "certificate-expired", mx: "mx.example.co.uk", ip: "203.0.113.5", sendingIp: "209.85.220.41", count: 30 }] });
	assert.equal(parseTlsReport(await unpackTls(new TextEncoder().encode(GOOGLE))).reportId, "2026-10-24T00:00:00Z_example.co.uk");
	assert.throws(() => parseTlsReport("<feedback/>"), TlsReportError);
	assert.throws(() => parseTlsReport('{"policies":[]}'), TlsReportError);
});

test("the record to add", () => {
	const ours = "dmarc-reports@example.net";
	assert.equal(tlsRecord(null, ours), `v=TLSRPTv1; rua=mailto:${ours}`);
	assert.equal(tlsRecord("v=TLSRPTv1; rua=mailto:tls@example.co.uk", ours), `v=TLSRPTv1; rua=mailto:tls@example.co.uk,mailto:${ours}`);
	assert.equal(tlsRecord(`v=TLSRPTv1; rua=mailto:${ours}`, ours), `v=TLSRPTv1; rua=mailto:${ours}`);
	assert.equal(tlsRecordHasUs(`v=TLSRPTv1; rua=mailto:${ours}`, ours), true);
	assert.equal(tlsRecordHasUs("v=TLSRPTv1; rua=mailto:tls@example.co.uk", ours), false);
});

test("the summary and the alert", () => {
	const rows = [{ org: "Google Inc.", end_at: end, policy_type: "sts", success: 970, failure: 30, details: JSON.stringify(parseTlsReport(GOOGLE).policies[0].failures) },
		{ org: "Microsoft Corporation", end_at: end, policy_type: "no-policy-found", success: 100, failure: 0, details: null }];
	const s = summariseTls(rows, "example.co.uk");
	assert.equal(s.rate, 97);
	assert.equal(s.policy, "sts");
	assert.deepEqual(s.problems.map((p) => [p.result, p.count, p.mx]), [["certificate-expired", 30, ["mx.example.co.uk"]]]);
	const now = new Date();
	const a = tlsAlert("example.co.uk", s, null, now, "https://dmarc.example.net/?domain=example.co.uk")!;
	assert.match(a.subject, /wasn't sent encrypted/);
	assert.match(a.text, /certificate has expired \(mx\.example\.co\.uk\)/);
	assert.equal(tlsAlert("example.co.uk", s, new Date(now.getTime() - 86_400_000).toISOString(), now, "x"), null);
	assert.equal(tlsAlert("example.co.uk", summariseTls([rows[1]], "example.co.uk"), null, now, "x"), null);
});

test("reports by email are kept once, for the right domain only", async () => {
	const { db } = fakeD1();
	const mime = (json: string) => new TextEncoder().encode([
		"From: noreply-smtp-tls-reporting@google.com", "To: dmarc-reports@example.net", "Subject: Report Domain: example.co.uk", "MIME-Version: 1.0",
		'Content-Type: multipart/report; boundary="b"; report-type=tlsrpt', "", "--b", "Content-Type: text/plain", "", "Report", "--b",
		'Content-Type: application/tlsrpt+gzip; name="report.json.gz"', 'Content-Disposition: attachment; filename="report.json.gz"', "Content-Transfer-Encoding: base64", "",
		gzipSync(json).toString("base64"), "--b--", ""].join("\r\n"));
	await db.prepare("INSERT INTO domains (domain) VALUES ('example.co.uk')").run();
	assert.deepEqual(await takeMail(db, mime(GOOGLE), resolve), { dmarc: 0, tls: 1 });
	assert.deepEqual(await takeMail(db, mime(GOOGLE), resolve), { dmarc: 0, tls: 0 });
	assert.deepEqual(await takeMail(db, mime(GOOGLE.replace(/example\.co\.uk/g, "other.com")), resolve), { dmarc: 0, tls: 0 });
	const rows = await tlsRows(db, "example.co.uk", 30);
	assert.equal(rows.length, 1);
	assert.equal(rows[0].failure, 30);
});
