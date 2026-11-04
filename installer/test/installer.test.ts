import { test } from "node:test";
import assert from "node:assert/strict";
import { UsageError, contentTypeFor, hostname, isManifest, isNewer, metadata, parseArgs, parseChoice, reportAddressFor, setupLink, type Manifest } from "../core.ts";

const ACCOUNT = "0123456789abcdef0123456789abcdef";

test("command line", () => {
	assert.equal(parseArgs([]).command, "help");
	assert.equal(parseArgs(["install"]).command, "setup");
	const o = parseArgs(["setup", "--domain", "example.com", "--location=enam", "-y"]);
	assert.deepEqual([o.command, o.domain, o.location, o.yes], ["setup", "example.com", "enam", true]);
	assert.equal(parseArgs(["setup", "--trial"]).domain, "");
	assert.throws(() => parseArgs(["setup", "--token", "abc"]), UsageError);
	assert.throws(() => parseArgs(["nope"]), UsageError);
	assert.throws(() => parseArgs(["setup", "--domain"]), UsageError);
});

test("choices", () => {
	assert.equal(parseChoice({ accountId: "nope" }), null);
	assert.equal(parseChoice({ accountId: ACCOUNT, domain: "not a domain" }), null);
	assert.equal(parseChoice({ accountId: ACCOUNT, location: "mars" }), null);
	const c = parseChoice({ accountId: ACCOUNT, domain: "Example.COM.", subdomain: "Reports" })!;
	assert.deepEqual(c, { accountId: ACCOUNT, domain: "example.com", subdomain: "reports", location: "weur" });
	assert.equal(hostname(c), "reports.example.com");
	const trial = parseChoice({ accountId: ACCOUNT, domain: "" })!;
	assert.equal(trial.domain, null);
	assert.equal(hostname(trial, "paul"), "dmarc-reports.paul.workers.dev");
	assert.equal(reportAddressFor("example.com"), "dmarc-reports@example.com");
	assert.equal(setupLink("dmarc.example.com", "abc", "dmarc-reports@example.com"), "https://dmarc.example.com/?setup=abc&report=dmarc-reports%40example.com");
	assert.equal(setupLink("x.workers.dev", "abc"), "https://x.workers.dev/?setup=abc");
});

test("versions and files", () => {
	assert.ok(isNewer("1.10.0", "1.9.0"));
	assert.ok(!isNewer("1.0.0", "1.0.0"));
	assert.ok(isNewer("1.0.0", null));
	assert.equal(contentTypeFor("/app.js"), "application/javascript");
	assert.equal(contentTypeFor("/favicon.svg"), "image/svg+xml");
});

test("worker metadata keeps secrets and binds everything", () => {
	const m: Manifest = { schema: 1, product: "dmarc-reports", version: "1.0.0", builtAt: "", worker: { compatibilityDate: "2026-10-01", compatibilityFlags: ["nodejs_compat"], crons: [] }, headers: "/*\n  x: y", assets: [] };
	assert.ok(isManifest(m));
	assert.ok(!isManifest({ ...m, version: "../x" }));
	const meta = metadata(m, "db-id", "jwt") as { bindings: { type: string; name: string }[]; keep_bindings: string[]; assets: { config: Record<string, unknown> } };
	assert.deepEqual(meta.bindings.map((b) => b.name), ["DB", "ASSETS", "EMAIL", "APP_VERSION"]);
	assert.deepEqual(meta.keep_bindings, ["secret_text"]);
	assert.deepEqual(meta.assets.config.run_worker_first, ["/api/*"]);
	assert.equal(meta.assets.config._headers, "/*\n  x: y");
});
