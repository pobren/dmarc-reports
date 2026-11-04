// DMARC Reports: a Cloudflare Worker that takes in your domains' DMARC and TLS reports by email, explains them
// in plain English, and walks you safely from p=none to p=reject. Everything stays on your own Cloudflare account.
//
//   fetch      the app (public/) and its API (/api/*)
//   email      reports sent to your report address (Cloudflare Email Routing sends them here)
//   scheduled  the daily look at each domain, alerts and tidying (src/cron.ts)

import { changePassword, cleanEmail, me, setup, signedIn, signIn, signOut } from "./auth.ts";
import { getBrand, setBrand } from "./brand.ts";
import { runCron } from "./cron.ts";
import { ensureSchema, getSetting, json, setSetting, VERSION, type Env } from "./db.ts";
import { dohResolver } from "./dns.ts";
import { MAX_FILE } from "./dmarc-core.ts";
import { takeMail } from "./mail.ts";
import { handleReports, sharedView } from "./reports.ts";
import { mailer } from "./send.ts";

const SECURITY_HEADERS: Record<string, string> = {
	"content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
	"x-content-type-options": "nosniff",
	"referrer-policy": "no-referrer",
	"x-frame-options": "DENY",
	"permissions-policy": "camera=(), microphone=(), geolocation=()",
};

function secure(res: Response): Response {
	const out = new Response(res.body, res);
	for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
	out.headers.set("x-robots-tag", "noindex, nofollow");
	return out;
}

async function settings(request: Request, env: Env): Promise<Response> {
	if (request.method === "POST") {
		const b = await request.json<Record<string, unknown>>().catch(() => ({}) as Record<string, unknown>);
		for (const [field, key, label] of [["reportAddress", "report_address", "report address"], ["alertTo", "alert_to", "address for alerts"]] as const) {
			if (b[field] === undefined) continue;
			if (b[field] === null || b[field] === "") { await setSetting(env.DB, key, null); continue; }
			const email = cleanEmail(b[field]);
			if (!email) return json({ error: `The ${label} doesn't look like an email address.` }, 400);
			await setSetting(env.DB, key, email);
		}
	}
	const [reportAddress, alertTo, lastReportAt] = await Promise.all(["report_address", "alert_to", "last_report_at"].map((k) => getSetting(env.DB, k)));
	return json({ reportAddress, alertTo, lastReportAt, canEmail: !!env.EMAIL, version: env.APP_VERSION || VERSION });
}

async function testEmail(env: Env): Promise<Response> {
	const send = await mailer(env);
	if (!send) return json({ error: env.EMAIL ? "Add your report address and an address for alerts first." : "Sending email isn't switched on for this install. The README shows how." }, 400);
	const ok = await send("Test email", "Hello,\n\nThis is a test. Alerts and summaries will come to this address.");
	return ok ? json({ ok: true }) : json({ error: "Cloudflare didn't send it. The address for alerts must be verified under Email Routing › Destination addresses in your Cloudflare dashboard." }, 502);
}

async function api(request: Request, env: Env, path: string): Promise<Response> {
	const m = request.method;
	// Every change must come from this app's own pages.
	if (m !== "GET" && m !== "HEAD") {
		const origin = request.headers.get("origin");
		if (origin && origin !== new URL(request.url).origin) return json({ error: "Forbidden" }, 403);
	}
	if (path === "/api/me" && m === "GET") return me(request, env);
	if (path === "/api/brand" && m === "GET") return getBrand(env.DB);
	if (path === "/api/setup" && m === "POST") return setup(request, env);
	if (path === "/api/sign-in" && m === "POST") return signIn(request, env);
	if (path === "/api/sign-out" && m === "POST") return signOut();
	const share = /^\/api\/share\/([a-z0-9]{20})$/.exec(path);
	if (share && m === "GET") return sharedView(share[1], env.DB);

	if (!(await signedIn(request, env.DB))) return json({ error: "Please sign in." }, 401);
	// Remember where the app lives, for links in emails.
	const origin = new URL(request.url).origin;
	if ((await getSetting(env.DB, "origin")) !== origin) await setSetting(env.DB, "origin", origin);

	if (path === "/api/settings" && (m === "GET" || m === "POST")) return settings(request, env);
	if (path === "/api/brand" && m === "POST") return setBrand(request, env.DB);
	if (path === "/api/password" && m === "POST") return changePassword(request, env);
	if (path === "/api/test-email" && m === "POST") return testEmail(env);
	return (await handleReports(request, path, env.DB, dohResolver())) ?? json({ error: "Not found" }, 404);
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const path = new URL(request.url).pathname;
		if (path.startsWith("/api/")) {
			try {
				await ensureSchema(env.DB);
				return secure(await api(request, env, path));
			} catch (e) {
				console.error("api", e);
				return secure(json({ error: "Something went wrong. Please try again." }, 500));
			}
		}
		return secure(await env.ASSETS.fetch(request));
	},

	async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
		if (message.rawSize > MAX_FILE * 1.4) return message.setReject("Message too large");
		await ensureSchema(env.DB);
		await takeMail(env.DB, await new Response(message.raw).arrayBuffer(), dohResolver());
	},

	async scheduled(_event: ScheduledController, env: Env): Promise<void> {
		await ensureSchema(env.DB);
		await runCron(env, dohResolver(), await mailer(env), await getSetting(env.DB, "origin"));
	},
} satisfies ExportedHandler<Env>;
