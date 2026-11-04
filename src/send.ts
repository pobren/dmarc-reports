// Sending alert and summary emails to you, through Cloudflare Email Routing's send_email binding (EMAIL).
// Cloudflare only delivers these to an address you've verified under Email Routing › Destination addresses,
// and they're sent from your report address, whose domain already has Email Routing on.

import { EmailMessage } from "cloudflare:email";
import { getSetting, newId, type Env } from "./db.ts";
import { brandOf } from "./brand.ts";

export type Send = (subject: string, text: string) => Promise<boolean>;

/** Base64 in lines of 76, as email wants. */
function b64(text: string): string {
	const bytes = new TextEncoder().encode(text);
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/.{76}/g, "$&\r\n");
}

/** A header word that may hold any character (RFC 2047). */
const word = (s: string) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s).replace(/\r\n/g, "")}?=`);

export function mime(opts: { from: string; fromName: string; to: string; subject: string; text: string; domain: string }): string {
	return [
		`From: ${word(opts.fromName.replace(/["\r\n]/g, ""))} <${opts.from}>`,
		`To: <${opts.to}>`,
		`Subject: ${word(opts.subject.replace(/[\r\n]/g, " "))}`,
		`Date: ${new Date().toUTCString()}`,
		`Message-ID: <${newId(20)}@${opts.domain}>`,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"Auto-Submitted: auto-generated",
		"",
		b64(opts.text),
		"",
	].join("\r\n");
}

/** A sender for the alerts, or null when there's nowhere to send them (no EMAIL binding, report address or alert address). */
export async function mailer(env: Env): Promise<Send | null> {
	if (!env.EMAIL) return null;
	const [from, to, brand] = await Promise.all([getSetting(env.DB, "report_address"), getSetting(env.DB, "alert_to"), brandOf(env.DB)]);
	if (!from || !to) return null;
	const domain = from.split("@")[1];
	return async (subject, text) => {
		try {
			await env.EMAIL!.send(new EmailMessage(from, to, mime({ from, fromName: brand.name, to, subject, text, domain })));
			return true;
		} catch (e) {
			console.error("sending email", e);
			return false;
		}
	};
}
