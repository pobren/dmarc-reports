// The app's own parts: signing in, taking reports in by email, branding and the records it asks for.
// Run with `node --experimental-strip-types --test test/app.test.ts`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { fakeD1 } from "./fake-d1.ts";
import { checkPassword, hashPassword, same, setup, signedIn, signIn } from "../src/auth.ts";
import { brandOf, setBrand, DEFAULT_NAME } from "../src/brand.ts";
import { ownerDomain, takeMail } from "../src/mail.ts";
import { cleanDmarcDomain, externalRecordName } from "../src/reports.ts";
import { statements } from "../src/db.ts";
import { SCHEMA } from "../src/schema.ts";
import type { Env } from "../src/db.ts";

const resolve = async () => ({ status: 3, data: [] as string[] });
const GOOGLE = /const GOOGLE = `([\s\S]*?)`;/.exec(readFileSync(new URL("./dmarc.test.ts", import.meta.url), "utf8"))![1];
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
	new Request(`https://dmarc.example.net${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const cookieFrom = (r: Response) => (r.headers.get("set-cookie") ?? "").split(";")[0];

test("the schema splits into statements", () => {
	const all = SCHEMA.flatMap(statements);
	assert.ok(all.length > 10);
	assert.ok(all.every((s) => /^CREATE (TABLE|UNIQUE INDEX|INDEX) IF NOT EXISTS/.test(s)));
});

test("passwords are hashed and checked", async () => {
	const h = await hashPassword("correct horse battery", 1000);
	assert.match(h, /^pbkdf2\$1000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
	assert.equal(await checkPassword("correct horse battery", h), true);
	assert.equal(await checkPassword("wrong", h), false);
	assert.equal(await checkPassword("x", null), false);
	assert.equal(same("abc", "abc"), true);
	assert.equal(same("abc", "abd"), false);
	assert.equal(same("abc", "abcd"), false);
});

test("set-up needs your own code, works once, and signs you in", async () => {
	const { db } = fakeD1();
	const env = { DB: db, SETUP_TOKEN: "change-me-to-a-long-random-code" } as unknown as Env;
	assert.equal((await setup(post("/api/setup", { code: "change-me-to-a-long-random-code", password: "abcdefghijk" }), env)).status, 403);
	env.SETUP_TOKEN = "my-own-code-1234567890";
	assert.equal((await setup(post("/api/setup", { code: "nope", password: "abcdefghijk" }), env)).status, 403);
	assert.equal((await setup(post("/api/setup", { code: "my-own-code-1234567890", password: "short" }), env)).status, 400);
	const ok = await setup(post("/api/setup", { code: "my-own-code-1234567890", password: "abcdefghijk", reportAddress: "Dmarc@Example.net" }), env);
	assert.equal(ok.status, 200);
	const cookie = cookieFrom(ok);
	assert.equal(await signedIn(new Request("https://x/", { headers: { cookie } }), db), true);
	assert.equal(await signedIn(new Request("https://x/", { headers: { cookie: cookie.replace(/.$/, (c) => (c === "0" ? "1" : "0")) } }), db), false);
	// The same code can't be used again.
	assert.equal((await setup(post("/api/setup", { code: "my-own-code-1234567890", password: "abcdefghijk2" }), env)).status, 403);
	assert.equal((await signIn(post("/api/sign-in", { password: "wrong-password" }), env)).status, 403);
	assert.equal((await signIn(post("/api/sign-in", { password: "abcdefghijk" }), env)).status, 200);
	// A new code resets the password and signs everyone else out.
	env.SETUP_TOKEN = "another-code-1234567890";
	assert.equal((await setup(post("/api/setup", { code: "another-code-1234567890", password: "a-new-password" }), env)).status, 200);
	assert.equal(await signedIn(new Request("https://x/", { headers: { cookie } }), db), false);
});

test("wrong passwords are slowed down", async () => {
	const { db } = fakeD1();
	const env = { DB: db, SETUP_TOKEN: "my-own-code-1234567890" } as unknown as Env;
	await setup(post("/api/setup", { code: "my-own-code-1234567890", password: "abcdefghijk" }), env);
	for (let i = 0; i < 8; i++) assert.equal((await signIn(post("/api/sign-in", { password: "nope" }, { "cf-connecting-ip": "203.0.113.1" }), env)).status, 403);
	assert.equal((await signIn(post("/api/sign-in", { password: "abcdefghijk" }, { "cf-connecting-ip": "203.0.113.1" }), env)).status, 429);
	assert.equal((await signIn(post("/api/sign-in", { password: "abcdefghijk" }, { "cf-connecting-ip": "203.0.113.2" }), env)).status, 200);
});

test("DMARC reports by email are kept once, for your domains only", async () => {
	const { db } = fakeD1();
	const mime = (xml: string) => new TextEncoder().encode([
		"From: noreply-dmarc-support@google.com", "To: dmarc-reports@example.net", "Subject: Report domain: example.co.uk", "MIME-Version: 1.0",
		'Content-Type: multipart/mixed; boundary="b"', "", "--b", "Content-Type: text/plain", "", "Report", "--b",
		'Content-Type: application/gzip; name="r.xml.gz"', 'Content-Disposition: attachment; filename="r.xml.gz"', "Content-Transfer-Encoding: base64", "",
		gzipSync(xml).toString("base64"), "--b--", ""].join("\r\n"));
	assert.deepEqual(await takeMail(db, mime(GOOGLE), resolve), { dmarc: 0, tls: 0 });
	await db.prepare("INSERT INTO domains (domain) VALUES ('example.co.uk')").run();
	assert.deepEqual(await takeMail(db, mime(GOOGLE), resolve), { dmarc: 1, tls: 0 });
	assert.deepEqual(await takeMail(db, mime(GOOGLE), resolve), { dmarc: 0, tls: 0 });
	assert.deepEqual(await takeMail(db, mime(GOOGLE.replace(/example\.co\.uk/g, "other.com")), resolve), { dmarc: 0, tls: 0 });
	// A subdomain's report counts for the domain above it.
	assert.deepEqual(await takeMail(db, mime(GOOGLE.replace("<domain>example.co.uk</domain><adkim>", "<domain>shop.example.co.uk</domain><adkim>").replace("1234567890", "222")), resolve), { dmarc: 1, tls: 0 });
	const n = await db.prepare("SELECT COUNT(*) AS n, SUM(messages) AS m FROM reports WHERE domain = 'example.co.uk'").first<{ n: number; m: number }>();
	assert.equal(n?.n, 2);
});

test("which domain a report belongs to", () => {
	assert.equal(ownerDomain("example.co.uk", ["example.co.uk", "other.com"]), "example.co.uk");
	assert.equal(ownerDomain("Mail.Shop.Example.co.uk.", ["example.co.uk", "shop.example.co.uk"]), "shop.example.co.uk");
	assert.equal(ownerDomain("notexample.co.uk", ["example.co.uk"]), null);
	assert.equal(cleanDmarcDomain("https://www.Example.co.uk/page"), "example.co.uk");
	assert.equal(cleanDmarcDomain("not a domain"), null);
});

test("a report address on another domain needs that domain's say-so", () => {
	assert.equal(externalRecordName("example.co.uk", "dmarc@example.co.uk"), null);
	assert.equal(externalRecordName("shop.example.co.uk", "dmarc@example.co.uk"), null);
	assert.equal(externalRecordName("example.co.uk", "dmarc@reports.example.net"), "example.co.uk._report._dmarc.reports.example.net");
});

test("branding: your own name, colour, logo and support address", async () => {
	const { db } = fakeD1();
	assert.equal((await brandOf(db)).name, DEFAULT_NAME);
	assert.equal((await brandOf(db)).custom, false);
	const set = (b: unknown) => setBrand(post("/api/brand", b), db);
	assert.equal((await set({ colour: "red" })).status, 400);
	assert.equal((await set({ logo: "data:text/html;base64,PGgxPg==" })).status, 400);
	assert.equal((await set({ support: "nope" })).status, 400);
	assert.equal((await set({ name: "x".repeat(41) })).status, 400);
	const ok = await set({ name: "Brightwell <IT>", colour: "#0F766E", support: "Help@Brightwell.example", logo: "data:image/png;base64,iVBORw0KGgo=" });
	assert.equal(ok.status, 200);
	const b = await brandOf(db);
	assert.deepEqual(b, { name: "Brightwell IT", colour: "#0f766e", logo: "data:image/png;base64,iVBORw0KGgo=", support: "help@brightwell.example", custom: true });
	await set({ name: null, colour: null, logo: null, support: null });
	assert.equal((await brandOf(db)).custom, false);
});
