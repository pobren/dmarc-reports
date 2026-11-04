// Cloudflare Turnstile, the free robot check, on set-up and sign-in. Off until you add both keys to the Worker as
// secrets: TURNSTILE_SITE_KEY and TURNSTILE_SECRET (secrets, so updates keep them). Make the widget under Turnstile in
// the Cloudflare dashboard, with this app's web address as its hostname. The page sends the widget's answer as "ts"
// (public/app.js, robotCheck).

export type TurnstileEnv = { TURNSTILE_SITE_KEY?: string; TURNSTILE_SECRET?: string };

/** The site key the page shows, or null when Turnstile is off. */
export function turnstileKey(env: TurnstileEnv): string | null {
	return env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET ? env.TURNSTILE_SITE_KEY : null;
}

export const ROBOT_ERROR = "We couldn't check you're a person. Please try again, and tick the box if one appears.";

/** True when Turnstile is off, or Cloudflare says the answer is genuine. */
export async function turnstileOk(env: TurnstileEnv, request: Request, token: unknown, verify: typeof fetch = fetch): Promise<boolean> {
	if (!turnstileKey(env)) return true;
	if (typeof token !== "string" || !token || token.length > 2048) return false;
	const body = new FormData();
	body.append("secret", env.TURNSTILE_SECRET!);
	body.append("response", token);
	const ip = request.headers.get("cf-connecting-ip");
	if (ip) body.append("remoteip", ip);
	try {
		const res = await verify("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
		return Boolean(((await res.json()) as { success?: boolean }).success);
	} catch (e) {
		// Cloudflare's check itself failing shouldn't lock you out of your own app: the password limits still apply.
		console.error("turnstile: siteverify failed", e);
		return true;
	}
}
