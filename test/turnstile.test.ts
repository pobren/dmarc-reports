import assert from "node:assert/strict";
import { test } from "node:test";
import { turnstileKey, turnstileOk } from "../src/turnstile.ts";

const req = new Request("https://dmarc.example.com/api/sign-in", { method: "POST", headers: { "cf-connecting-ip": "192.0.2.1" } });
const cloudflare = (good: string) => (async (_u: unknown, init?: RequestInit) => new Response(JSON.stringify({ success: (init!.body as FormData).get("response") === good }))) as typeof fetch;

test("Turnstile is off until both keys are set", async () => {
	assert.equal(turnstileKey({}), null);
	assert.equal(turnstileKey({ TURNSTILE_SITE_KEY: "site" }), null);
	assert.equal(turnstileKey({ TURNSTILE_SECRET: "secret" }), null);
	assert.equal(turnstileKey({ TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" }), "site");
	assert.equal(await turnstileOk({ TURNSTILE_SITE_KEY: "site" }, req, undefined), true);
});

test("Turnstile needs a genuine answer once it's on", async () => {
	const env = { TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" };
	const verify = cloudflare("good");
	assert.equal(await turnstileOk(env, req, undefined, verify), false);
	assert.equal(await turnstileOk(env, req, "", verify), false);
	assert.equal(await turnstileOk(env, req, "bad", verify), false);
	assert.equal(await turnstileOk(env, req, "x".repeat(3000), verify), false);
	assert.equal(await turnstileOk(env, req, "good", verify), true);
});

test("Cloudflare being unreachable doesn't lock the owner out", async () => {
	const env = { TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET: "secret" };
	const down = (async () => { throw new Error("offline"); }) as typeof fetch;
	assert.equal(await turnstileOk(env, req, "anything", down), true);
});
