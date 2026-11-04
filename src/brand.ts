// Your own name, logo and colour on the app, its emails and shared links (white label). Set under Settings ›
// Branding. Running it under your own brand for clients needs a commercial licence: see LICENSE.
//
//   GET  /api/brand    Anyone (the sign-in page and shared links show it)
//   POST /api/brand    { name?, colour?, logo?, support? } (signed in). null puts one back to the default.

import { getSetting, json, setSetting } from "./db.ts";
import { cleanEmail } from "./auth.ts";

export const DEFAULT_NAME = "DMARC Reports";
export const DEFAULT_COLOUR = "#4338ca";
/** Logos are kept in the database as a data: address, so keep them small. */
const MAX_LOGO = 150 * 1024;

export interface Brand {
	name: string;
	colour: string;
	/** A data: address (PNG, JPEG, WebP or SVG), or null for the standard shield. */
	logo: string | null;
	/** Where people go for help: an email address, or null. */
	support: string | null;
	/** True when any of it has been changed. */
	custom: boolean;
}

export async function brandOf(db: D1Database): Promise<Brand> {
	const raw = await getSetting(db, "brand");
	let b: Partial<Brand> = {};
	try { b = raw ? JSON.parse(raw) : {}; } catch { /* the defaults */ }
	const name = typeof b.name === "string" && b.name.trim() ? b.name.trim() : DEFAULT_NAME;
	const colour = typeof b.colour === "string" && /^#[0-9a-f]{6}$/i.test(b.colour) ? b.colour.toLowerCase() : DEFAULT_COLOUR;
	const logo = typeof b.logo === "string" && /^data:image\/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(b.logo) ? b.logo : null;
	const support = typeof b.support === "string" ? cleanEmail(b.support) : null;
	return { name, colour, logo, support, custom: name !== DEFAULT_NAME || colour !== DEFAULT_COLOUR || !!logo || !!support };
}

export async function getBrand(db: D1Database): Promise<Response> {
	return json(await brandOf(db), 200, { "cache-control": "no-cache" });
}

export async function setBrand(request: Request, db: D1Database): Promise<Response> {
	const b = await request.json<Record<string, unknown>>().catch(() => ({}) as Record<string, unknown>);
	const now = await brandOf(db);
	const next = { name: now.name, colour: now.colour, logo: now.logo, support: now.support };
	if (b.name !== undefined) {
		if (b.name === null || b.name === "") next.name = DEFAULT_NAME;
		else if (typeof b.name !== "string" || b.name.trim().length > 40) return json({ error: "Please keep the name to 40 characters or fewer." }, 400);
		else next.name = b.name.trim().replace(/[<>\r\n]/g, "");
	}
	if (b.colour !== undefined) {
		if (b.colour === null || b.colour === "") next.colour = DEFAULT_COLOUR;
		else if (typeof b.colour !== "string" || !/^#[0-9a-f]{6}$/i.test(b.colour)) return json({ error: "Please choose a colour such as #4338ca." }, 400);
		else next.colour = b.colour.toLowerCase();
	}
	if (b.logo !== undefined) {
		if (b.logo === null || b.logo === "") next.logo = null;
		else if (typeof b.logo !== "string" || !/^data:image\/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(b.logo)) return json({ error: "Please choose a PNG, JPEG, WebP or SVG picture." }, 400);
		else if (b.logo.length > MAX_LOGO * 1.37) return json({ error: "That picture is too big. Please use one under 150 KB." }, 400);
		else next.logo = b.logo;
	}
	if (b.support !== undefined) {
		if (b.support === null || b.support === "") next.support = null;
		else if (!cleanEmail(b.support)) return json({ error: "The support address doesn't look like an email address." }, 400);
		else next.support = cleanEmail(b.support);
	}
	await setSetting(db, "brand", JSON.stringify(next));
	return json(await brandOf(db));
}
