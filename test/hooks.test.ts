import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { cleanHookUrl, hookHeaders, maskUrl } from "../src/hooks.ts";

test("webhooks are signed like Mail App's and Site Watch's", async () => {
	const body = JSON.stringify({ id: "evt_1", type: "test", data: {} });
	const h = await hookHeaders("whsec_abc", "test", "evt_1", body, 1_700_000_000_000);
	assert.equal(h["dmarc-reports-event"], "test");
	assert.equal(h["dmarc-reports-delivery"], "evt_1");
	const want = createHmac("sha256", "whsec_abc").update(`1700000000.${body}`).digest("hex");
	assert.equal(h["dmarc-reports-signature"], `t=1700000000,v1=${want}`);
});

test("webhook addresses must be https", () => {
	assert.equal(cleanHookUrl("http://example.com/hook"), null);
	assert.equal(cleanHookUrl("https://user:pw@example.com/"), null);
	assert.equal(cleanHookUrl("not a url"), null);
	assert.equal(cleanHookUrl(" https://example.com/hook "), "https://example.com/hook");
	assert.equal(maskUrl("https://hooks.example.com/abcdefghijklmnop"), "hooks.example.com/abcdefg…");
});
