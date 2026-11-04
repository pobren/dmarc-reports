// DMARC Reports: reading DMARC aggregate reports and explaining them in plain English.
// Pure functions only (no database, no network), so they can be tested with node --test.
//
// A report arrives as XML, usually gzipped (.xml.gz) or zipped (.zip). unpackReport() opens it with
// size caps (a small zip can unpack to gigabytes), parseReport() reads the XML with a tiny parser that
// refuses DOCTYPE and entities outright (so no outside files, no entity bombs), senderFor() names who
// sent each batch of mail, and analyse() turns the rows into a verdict and instructions per sender.
// rollout() is the step-by-step plan from p=none to p=reject.

/** Biggest report file we accept (compressed, or plain XML). */
export const MAX_FILE = 5 * 1024 * 1024;
/** Biggest it may become once unzipped, across every file inside it. Stops zip bombs. */
export const MAX_UNPACKED = 20 * 1024 * 1024;
/** Files read from one zip. Real reports hold one. */
const MAX_ZIP_FILES = 10;
/** Rows read from one report. Big senders' reports hold a few hundred at most. */
export const MAX_RECORDS = 5000;

// --- Opening the file ---------------------------------------------------------------------------

export class ReportError extends Error {}

/** Unpacks with a running total, giving up as soon as it passes `cap`. */
async function inflate(bytes: Uint8Array, format: "gzip" | "deflate-raw", cap: number): Promise<Uint8Array> {
	const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
	const reader = stream.getReader();
	const parts: Uint8Array[] = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > cap) throw new ReportError("This report is too big once unzipped. We read reports up to 20 MB.");
			parts.push(value);
		}
	} catch (e) {
		await reader.cancel().catch(() => undefined);
		if (e instanceof ReportError) throw e;
		throw new ReportError("This file looks damaged: we couldn't unzip it.");
	}
	const out = new Uint8Array(size);
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.byteLength;
	}
	return out;
}

const u16 = (b: Uint8Array, i: number) => b[i] | (b[i + 1] << 8);
const u32 = (b: Uint8Array, i: number) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;

/** The .xml files inside a zip, from its central directory. Only "stored" and "deflate" are used by real reports. */
async function unzip(b: Uint8Array): Promise<{ name: string; data: Uint8Array }[]> {
	let end = -1;
	for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65_535); i--) {
		if (u32(b, i) === 0x06054b50) { end = i; break; }
	}
	if (end < 0) throw new ReportError("This file looks damaged: we couldn't open the zip.");
	const count = u16(b, end + 10);
	let at = u32(b, end + 16);
	const files: { name: string; data: Uint8Array }[] = [];
	let total = 0;
	for (let n = 0; n < count && files.length < MAX_ZIP_FILES; n++) {
		if (at + 46 > b.length || u32(b, at) !== 0x02014b50) throw new ReportError("This file looks damaged: we couldn't open the zip.");
		const method = u16(b, at + 10);
		const packed = u32(b, at + 20);
		const size = u32(b, at + 24);
		const nameLen = u16(b, at + 28);
		const extraLen = u16(b, at + 30);
		const commentLen = u16(b, at + 32);
		const local = u32(b, at + 42);
		const name = new TextDecoder().decode(b.subarray(at + 46, at + 46 + nameLen));
		at += 46 + nameLen + extraLen + commentLen;
		if (name.endsWith("/") || !/\.xml$/i.test(name)) continue;
		if (local + 30 > b.length || u32(b, local) !== 0x04034b50) throw new ReportError("This file looks damaged: we couldn't open the zip.");
		const start = local + 30 + u16(b, local + 26) + u16(b, local + 28);
		const body = b.subarray(start, start + packed);
		if (body.length < packed) throw new ReportError("This file looks damaged: we couldn't open the zip.");
		// The size in the directory can lie, so the total counts what each file really unpacked to.
		if (total + size > MAX_UNPACKED) throw new ReportError("This report is too big once unzipped. We read reports up to 20 MB.");
		let data: Uint8Array;
		if (method === 0) data = body;
		else if (method === 8) data = await inflate(body, "deflate-raw", MAX_UNPACKED - total);
		else throw new ReportError("This zip uses a kind of compression we can't read.");
		total += data.length;
		if (total > MAX_UNPACKED) throw new ReportError("This report is too big once unzipped. We read reports up to 20 MB.");
		files.push({ name, data });
	}
	return files;
}

/**
 * The XML report(s) in a file as mail providers send them: plain .xml, .xml.gz or .zip.
 * Throws ReportError with a plain-English reason when it isn't one.
 */
export async function unpackReport(bytes: Uint8Array, maxFile = MAX_FILE): Promise<string[]> {
	if (bytes.byteLength > maxFile) throw new ReportError(`This file is too big. We read report files up to ${maxFile / 1048576} MB.`);
	let texts: Uint8Array[];
	if (bytes[0] === 0x1f && bytes[1] === 0x8b) texts = [await inflate(bytes, "gzip", MAX_UNPACKED)];
	else if (bytes[0] === 0x50 && bytes[1] === 0x4b) texts = (await unzip(bytes)).map((f) => f.data);
	else texts = [bytes];
	const xml = texts.map((t) => new TextDecoder().decode(t)).filter((t) => /<feedback[\s>]/.test(t.slice(0, 4096)));
	if (!xml.length) throw new ReportError("This doesn't look like a DMARC report. Reports are .xml, .xml.gz or .zip files from addresses such as noreply-dmarc-support@google.com.");
	return xml;
}

// --- Reading the XML ----------------------------------------------------------------------------

interface Node {
	name: string;
	kids: Node[];
	text: string;
}

const ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function decode(s: string): string {
	return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (all, e: string) => {
		if (e[0] === "#") {
			const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
			return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
		}
		return ENTITIES[e.toLowerCase()] ?? all;
	});
}

/**
 * A deliberately small XML reader: elements and text only. DOCTYPE declarations (and so any entity
 * other than the five built-in ones) are refused, so nothing in a report can make us fetch or expand anything.
 */
export function parseXml(xml: string): Node {
	if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new ReportError("This report contains a DOCTYPE, which we don't read for safety.");
	const body = xml.replace(/^﻿/, "").replace(/<\?[\s\S]*?\?>/g, "").replace(/<!--[\s\S]*?-->/g, "");
	const root: Node = { name: "#root", kids: [], text: "" };
	const stack: Node[] = [root];
	const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w.:-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>|([^<]+)/g;
	let m: RegExpExecArray | null;
	let last = 0;
	while ((m = re.exec(body))) {
		if (m.index !== last && body.slice(last, m.index).trim()) throw new ReportError("This report's XML is damaged.");
		last = re.lastIndex;
		const top = stack[stack.length - 1];
		if (m[1] !== undefined) top.text += m[1];
		else if (m[6] !== undefined) top.text += decode(m[6]);
		else {
			const name = m[3].replace(/^.*:/, "");
			if (m[2]) {
				if (stack.length < 2 || top.name !== name) throw new ReportError("This report's XML is damaged.");
				stack.pop();
			} else {
				const node: Node = { name, kids: [], text: "" };
				top.kids.push(node);
				if (!m[5]) {
					if (stack.length > 32) throw new ReportError("This report's XML is damaged.");
					stack.push(node);
				}
			}
		}
	}
	if (last !== body.length && body.slice(last).trim()) throw new ReportError("This report's XML is damaged.");
	if (stack.length !== 1) throw new ReportError("This report's XML is cut short.");
	return root;
}

const kid = (n: Node | undefined, name: string) => n?.kids.find((k) => k.name === name);
const kids = (n: Node | undefined, name: string) => n?.kids.filter((k) => k.name === name) ?? [];
const text = (n: Node | undefined, name: string) => (kid(n, name)?.text ?? "").trim();

export type Result = "pass" | "fail";

export interface Row {
	ip: string;
	count: number;
	/** What the receiver did: none (delivered), quarantine (spam folder) or reject. */
	disposition: string;
	/** DMARC's own verdicts: whether DKIM and SPF passed *and* matched the From domain. */
	dkim: Result;
	spf: Result;
	headerFrom: string;
	/** The raw DKIM signatures checked (d= domain and result), and the SPF domain checked. */
	dkimAuth: { domain: string; selector: string; result: string }[];
	spfAuth: { domain: string; result: string } | null;
	/** Why the receiver let failing mail through, when it says (forwarded, mailing_list, trusted_forwarder…). */
	reasons?: string[];
}

export interface Policy {
	domain: string;
	p: string;
	sp: string;
	pct: number;
	adkim: string;
	aspf: string;
}

export interface Report {
	org: string;
	reportId: string;
	begin: string;
	end: string;
	policy: Policy;
	rows: Row[];
}

const ISO = (secs: string) => {
	const n = Number(secs);
	return Number.isFinite(n) && n > 0 ? new Date(n * 1000).toISOString().replace(/\.\d{3}Z$/, "Z") : "";
};

const pf = (s: string): Result => (s.toLowerCase() === "pass" ? "pass" : "fail");

/** Reads one aggregate report. Throws ReportError when the XML isn't a DMARC report. */
export function parseReport(xml: string): Report {
	const feedback = kid(parseXml(xml), "feedback");
	const meta = kid(feedback, "report_metadata");
	const pol = kid(feedback, "policy_published");
	const domain = text(pol, "domain").toLowerCase().replace(/\.$/, "");
	if (!feedback || !meta || !pol || !domain) throw new ReportError("This doesn't look like a DMARC report: it has no report details or policy.");
	const range = kid(meta, "date_range");
	const records = kids(feedback, "record");
	if (records.length > MAX_RECORDS) throw new ReportError(`This report has more than ${MAX_RECORDS.toLocaleString("en-GB")} rows, which is more than we read.`);
	const rows: Row[] = [];
	for (const r of records) {
		const row = kid(r, "row");
		const evaluated = kid(row, "policy_evaluated");
		const auth = kid(r, "auth_results");
		const ip = text(row, "source_ip");
		const count = Math.max(0, Math.min(1e9, Math.floor(Number(text(row, "count")) || 0)));
		if (!ip || !count) continue;
		const spf = kid(auth, "spf");
		rows.push({
			ip: ip.slice(0, 45),
			count,
			disposition: (text(evaluated, "disposition") || "none").toLowerCase().slice(0, 20),
			dkim: pf(text(evaluated, "dkim")),
			spf: pf(text(evaluated, "spf")),
			headerFrom: (text(kid(r, "identifiers"), "header_from") || domain).toLowerCase().slice(0, 253),
			dkimAuth: kids(auth, "dkim").slice(0, 5).map((d) => ({
				domain: text(d, "domain").toLowerCase().slice(0, 253), selector: text(d, "selector").slice(0, 63), result: text(d, "result").toLowerCase().slice(0, 20),
			})),
			spfAuth: spf ? { domain: text(spf, "domain").toLowerCase().slice(0, 253), result: text(spf, "result").toLowerCase().slice(0, 20) } : null,
			reasons: kids(evaluated, "reason").slice(0, 5).map((x) => text(x, "type").toLowerCase().slice(0, 30)).filter(Boolean),
		});
	}
	const pct = Number(text(pol, "pct"));
	return {
		org: (text(meta, "org_name") || text(meta, "email") || "Unknown").slice(0, 120),
		reportId: (text(meta, "report_id") || "").slice(0, 200),
		begin: ISO(text(range, "begin")),
		end: ISO(text(range, "end")),
		policy: {
			domain,
			p: (text(pol, "p") || "none").toLowerCase(),
			sp: text(pol, "sp").toLowerCase(),
			pct: Number.isFinite(pct) && text(pol, "pct") !== "" ? Math.max(0, Math.min(100, pct)) : 100,
			adkim: (text(pol, "adkim") || "r").toLowerCase(),
			aspf: (text(pol, "aspf") || "r").toLowerCase(),
		},
		rows,
	};
}

// --- Who sent it --------------------------------------------------------------------------------

export interface Service {
	id: string;
	name: string;
	/** Matches the DKIM d= domains, the SPF domain and the server's reverse DNS name. */
	match: RegExp;
	/** True for mailbox providers that also forward people's mail (so failures may be forwarding). */
	mailbox?: boolean;
	/** True for sending services other apps run on, so we can say "Atlassian via Amazon SES". */
	infra?: boolean;
	/** How to make it sign as you. */
	dkim: string[];
	help?: string;
}

const ends = (...names: string[]) => new RegExp(`(^|\\.)(${names.map((n) => n.replace(/\./g, "\\.")).join("|")})$`);

/** Services we can name, and how to set up DKIM in each, in their own menu words. */
export const SERVICES: Service[] = [
	{ id: "google", name: "Google Workspace / Gmail", mailbox: true, match: ends("google.com", "googlemail.com", "gappssmtp.com", "1e100.net"),
		dkim: ["Sign in to admin.google.com.", "Open Apps › Google Workspace › Gmail › Authenticate email.", "Choose your domain, press Generate new record, and add the TXT record it shows to your DNS.", "Come back to the same page and press Start authentication."],
		help: "https://support.google.com/a/answer/180504" },
	{ id: "microsoft", name: "Microsoft 365 / Outlook", mailbox: true, match: ends("outlook.com", "protection.outlook.com", "onmicrosoft.com", "hotmail.com", "office365.com"),
		dkim: ["Sign in to security.microsoft.com.", "Open Email & collaboration › Policies & rules › Threat policies › Email authentication settings, then the DKIM tab.", "Choose your domain and add the two CNAME records it shows to your DNS.", "Switch on Sign messages for this domain with DKIM signatures."],
		help: "https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure" },
	{ id: "ses", infra: true, name: "Amazon SES", match: ends("amazonses.com"),
		dkim: ["Sign in to the AWS console and open Amazon SES › Identities.", "Choose your domain (or create it) and turn on Easy DKIM.", "Add the three CNAME records it shows to your DNS.", "Optional: set a custom MAIL FROM domain so SPF matches too."],
		help: "https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-easy.html" },
	{ id: "cloudflare", name: "Cloudflare email (Email Routing, Email Sending)", match: ends("cloudflare-email.net", "cloudflare-email.com", "cloudflare.net"),
		dkim: ["Sign in to dash.cloudflare.com and choose your domain.", "Open Email › Email Sending (or Email Routing › Settings) and check the DNS records it lists are all added."] },
	{ id: "mailchimp", name: "Mailchimp", match: ends("mcsv.net", "mcdlv.net", "rsgsv.net", "mailchimpapp.net", "mailchimp.com"),
		dkim: ["Sign in to Mailchimp.", "Open your profile › Account & billing › Domains.", "Choose Authenticate next to your domain and add the two CNAME records it shows to your DNS.", "Back in Mailchimp, press Verify."],
		help: "https://mailchimp.com/help/set-up-email-domain-authentication/" },
	{ id: "mandrill", infra: true, name: "Mandrill (Mailchimp Transactional)", match: ends("mandrillapp.com"),
		dkim: ["Sign in to Mandrill and open Settings › Sending domains.", "Add your domain and the DKIM and SPF records it shows to your DNS.", "Press Test DNS settings."] },
	{ id: "sendgrid", infra: true, name: "SendGrid", match: ends("sendgrid.net", "sendgrid.com"),
		dkim: ["Sign in to SendGrid and open Settings › Sender Authentication.", "Choose Authenticate Your Domain and follow the steps.", "Add the CNAME records it shows to your DNS, then press Verify."],
		help: "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication" },
	{ id: "mailgun", infra: true, name: "Mailgun", match: ends("mailgun.org", "mailgun.net", "mailgun.info"),
		dkim: ["Sign in to Mailgun and open Send › Sending › Domains.", "Add your domain and the TXT and CNAME records it shows to your DNS.", "Press Verify DNS settings."] },
	{ id: "postmark", infra: true, name: "Postmark", match: ends("mtasv.net", "postmarkapp.com", "pm.mtasv.net"),
		dkim: ["Sign in to Postmark and open Sender Signatures.", "Choose your domain, then DNS Settings.", "Add the DKIM TXT record and the Return-Path CNAME it shows to your DNS, then press Verify."] },
	{ id: "brevo", name: "Brevo (Sendinblue)", match: ends("sendinblue.com", "brevo.com", "brevosend.com", "sibmail.com"),
		dkim: ["Sign in to Brevo and open Senders, Domains & Dedicated IPs › Domains.", "Choose Authenticate next to your domain.", "Add the records it shows to your DNS, then press Authenticate this email domain."] },
	{ id: "zoho", name: "Zoho Mail", mailbox: true, match: ends("zoho.com", "zoho.eu", "zohomail.com", "zohomail.eu", "zeptomail.com"),
		dkim: ["Sign in to the Zoho Mail admin console.", "Open Domains, choose your domain, then Email configuration › DKIM.", "Add a selector, copy the TXT record to your DNS, then press Verify."] },
	{ id: "fastmail", name: "Fastmail", mailbox: true, match: ends("messagingengine.com", "fastmail.com", "fastmail.fm"),
		dkim: ["Sign in to Fastmail and open Settings › Domains.", "Choose your domain and check the DNS records it lists.", "Add the three DKIM CNAME records (fm1, fm2 and fm3) to your DNS."] },
	{ id: "proton", name: "Proton Mail", mailbox: true, match: ends("protonmail.ch", "proton.me", "protonmail.com"),
		dkim: ["Sign in to Proton Mail and open Settings › Domain names.", "Choose Review next to your domain, then the DKIM tab.", "Add the three CNAME records it shows to your DNS."] },
	{ id: "yahoo", name: "Yahoo / AOL", mailbox: true, match: ends("yahoo.com", "yahoodns.net", "aol.com"), dkim: [] },
	{ id: "icloud", name: "iCloud Mail", mailbox: true, match: ends("icloud.com", "me.com", "mac.com", "apple.com"),
		dkim: ["On iCloud.com, open Settings › Custom Email Domain.", "Choose your domain and check every record it lists is added to your DNS."] },
	{ id: "hubspot", name: "HubSpot", match: ends("hubspotemail.net", "hubspot.com", "hs-sites.com"),
		dkim: ["Sign in to HubSpot and open Settings › Content › Domains & URLs › Email sending domains.", "Choose Connect a sending domain and add the records it shows to your DNS."] },
	{ id: "klaviyo", name: "Klaviyo", match: ends("klaviyomail.com", "klaviyo.com"),
		dkim: ["Sign in to Klaviyo and open Settings › Domains.", "Set up a branded sending domain and add the records it shows to your DNS."] },
	{ id: "constantcontact", name: "Constant Contact", match: ends("constantcontact.com", "ccsend.com", "ctctcdn.com"),
		dkim: ["Sign in to Constant Contact and open My Settings › Email Authentication.", "Choose Authenticate and add the CNAME records it shows to your DNS."] },
	{ id: "campaignmonitor", name: "Campaign Monitor", match: ends("createsend.com", "cmail1.com", "cmail2.com", "cmail19.com", "cmail20.com"),
		dkim: ["Sign in to Campaign Monitor and open Account settings › Domains.", "Add your domain and the TXT record it shows to your DNS."] },
	{ id: "mailerlite", name: "MailerLite", match: ends("mlsend.com", "mailerlite.com", "mlsend2.com"),
		dkim: ["Sign in to MailerLite and open Account settings › Domains.", "Choose Authenticate next to your domain and add the records it shows to your DNS."] },
	{ id: "kit", name: "Kit (ConvertKit)", match: ends("convertkit.com", "ck.page", "kit.com", "convertkit-mail.com", "convertkit-mail2.com"),
		dkim: ["Sign in to Kit and open Settings › Email › Sending domain.", "Add your domain and the CNAME records it shows to your DNS."] },
	{ id: "mailjet", name: "Mailjet", match: ends("mailjet.com", "mjt.lu"),
		dkim: ["Sign in to Mailjet and open Account settings › Domains & sender addresses.", "Choose Setup SPF/DKIM authentication next to your domain and add the records to your DNS."] },
	{ id: "sparkpost", infra: true, name: "SparkPost", match: ends("sparkpostmail.com", "sparkpost.com"),
		dkim: ["Sign in to SparkPost and open Configuration › Domains.", "Add your sending domain and the DKIM TXT record it shows to your DNS."] },
	{ id: "zendesk", name: "Zendesk", match: ends("zendesk.com", "zdsys.com"),
		dkim: ["Sign in to Zendesk Admin Center and open Channels › Talk and email › Email.", "Under Digital signatures, turn on DKIM for your domain and add the two CNAME records it shows to your DNS."] },
	{ id: "freshdesk", name: "Freshdesk", match: ends("freshdesk.com", "freshemail.io", "freshworks.com"),
		dkim: ["Sign in to Freshdesk and open Admin › Email › DKIM settings.", "Choose your domain and add the CNAME records it shows to your DNS."] },
	{ id: "shopify", name: "Shopify", match: ends("shopify.com", "shopifyemail.com", "myshopify.com"),
		dkim: ["Sign in to Shopify and open Settings › Notifications › Sender email.", "Choose Authenticate domain and add the CNAME records it shows to your DNS."] },
	{ id: "intercom", name: "Intercom", match: ends("intercom-mail.com", "intercom.io"),
		dkim: ["Sign in to Intercom and open Settings › Channels › Email › Domains.", "Add your domain and the DKIM records it shows to your DNS."] },
	{ id: "squarespace", name: "Squarespace", match: ends("squarespace.com", "sqspmail.com"),
		dkim: ["Sign in to Squarespace and open Settings › Email Campaigns › Sender profile.", "Verify your domain and add the records it shows to your DNS."] },
	{ id: "wix", name: "Wix", match: ends("wix.com", "wixemails.com", "wixsite.com"), dkim: ["Ask Wix support how to authenticate your domain for Wix email marketing; they give you the DNS records to add."] },
	{ id: "salesforce", name: "Salesforce", match: ends("salesforce.com", "exacttarget.com", "force.com"),
		dkim: ["Sign in to Salesforce Setup and search for DKIM Keys.", "Create a key for your domain and add the CNAME records it shows to your DNS, then activate it."] },
	// Apps small businesses send from. Many run on Amazon SES or SendGrid, which
	// senderFor() names as "via".
	{ id: "xero", name: "Xero", match: ends("xero.com"),
		dkim: ["Sign in to Xero and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "quickbooks", name: "QuickBooks (Intuit)", match: ends("intuit.com", "quickbooks.com"),
		dkim: ["Sign in to QuickBooks and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "sage", name: "Sage", match: ends("sage.com", "sageone.com"),
		dkim: ["Sign in to Sage and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "freeagent", name: "FreeAgent", match: ends("freeagent.com"),
		dkim: ["Sign in to FreeAgent and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "stripe", name: "Stripe", match: ends("stripe.com"),
		dkim: ["Sign in to Stripe and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "gocardless", name: "GoCardless", match: ends("gocardless.com"),
		dkim: ["Sign in to GoCardless and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "paypal", name: "PayPal", match: ends("paypal.com"),
		dkim: ["Sign in to PayPal and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "square", name: "Square", match: ends("squareup.com"),
		dkim: ["Sign in to Square and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "calendly", name: "Calendly", match: ends("calendly.com"),
		dkim: ["Sign in to Calendly and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "atlassian", name: "Atlassian (Jira, Confluence)", match: ends("atlassian.net", "atlassian.com"),
		dkim: ["Sign in to Atlassian and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "monday", name: "monday.com", match: ends("monday.com"),
		dkim: ["Sign in to monday.com and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "zoom", name: "Zoom", match: ends("zoom.us"),
		dkim: ["Sign in to Zoom and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "slack", name: "Slack", match: ends("slack.com"),
		dkim: ["Sign in to Slack and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "github", name: "GitHub", match: ends("github.com"),
		dkim: ["Sign in to GitHub and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "pipedrive", name: "Pipedrive", match: ends("pipedrive.com"),
		dkim: ["Sign in to Pipedrive and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "activecampaign", name: "ActiveCampaign", match: ends("activecampaign.com"),
		dkim: ["Sign in to ActiveCampaign and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "substack", name: "Substack", match: ends("substack.com"),
		dkim: ["Sign in to Substack and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "beehiiv", name: "beehiiv", match: ends("beehiiv.com"),
		dkim: ["Sign in to beehiiv and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "customerio", name: "Customer.io", match: ends("customeriomail.com", "customer.io"),
		dkim: ["Sign in to Customer.io and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "helpscout", name: "Help Scout", match: ends("helpscout.net", "helpscout.com"),
		dkim: ["Sign in to Help Scout and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "front", name: "Front", match: ends("frontapp.com"),
		dkim: ["Sign in to Front and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "docusign", name: "DocuSign", match: ends("docusign.net", "docusign.com"),
		dkim: ["Sign in to DocuSign and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "dropboxsign", name: "Dropbox Sign", match: ends("hellosign.com"),
		dkim: ["Sign in to Dropbox Sign and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "eventbrite", name: "Eventbrite", match: ends("eventbrite.com"),
		dkim: ["Sign in to Eventbrite and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "typeform", name: "Typeform", match: ends("typeform.com"),
		dkim: ["Sign in to Typeform and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "smtp2go", infra: true, name: "SMTP2GO", match: ends("smtp2go.com"),
		dkim: ["Sign in to SMTP2GO and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "elasticemail", infra: true, name: "Elastic Email", match: ends("elasticemail.com"),
		dkim: ["Sign in to Elastic Email and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
	{ id: "resend", infra: true, name: "Resend", match: ends("resend.dev", "resend.com"),
		dkim: ["Sign in to Resend and find its email settings (often called sending domain, email authentication or DKIM).", "Add the DNS records it shows for your domain, then press Verify."] },
];

export interface Sender {
	/** A service id from SERVICES, or "other" for a server we can't name. */
	id: string;
	name: string;
	known: boolean;
}

/** The domain a reverse DNS name belongs to, roughly (last two labels, three for .co.uk style names). */
function baseOf(host: string): string {
	const parts = host.replace(/\.$/, "").split(".");
	const n = parts.length >= 3 && /^(co|org|ac|gov|com|net|ltd|plc|me)$/.test(parts[parts.length - 2]) && parts[parts.length - 1].length === 2 ? 3 : 2;
	return parts.slice(-n).join(".");
}

/**
 * Who sent a batch of mail, from the DKIM signatures, the SPF domain and the server's reverse DNS name.
 * Your own domain in DKIM or SPF says nothing about which service sent it, so it's skipped.
 */
export function senderFor(row: Pick<Row, "dkimAuth" | "spfAuth" | "ip">, own: string, ptr?: string | null): Sender {
	const mine = (d: string) => d === own || d.endsWith(`.${own}`);
	const clean = (n: string) => n.toLowerCase().replace(/\.$/, "");
	const find = (names: string[]) => names.map(clean).filter(Boolean).map((n) => SERVICES.find((x) => x.match.test(n))).find(Boolean);
	// The app that signed it (its own DKIM domain) names it best; the server and SPF domain say whose
	// infrastructure carried it, so Atlassian's mail through Amazon SES reads "Atlassian via Amazon SES".
	const signer = find(row.dkimAuth.map((d) => d.domain).filter((d) => d && !mine(d)));
	const carrier = find([ptr ?? "", row.spfAuth && !mine(row.spfAuth.domain) ? row.spfAuth.domain : ""]);
	if (signer && carrier && signer.id !== carrier.id && carrier.infra && !signer.infra) return { id: signer.id, name: `${signer.name} via ${carrier.name}`, known: true };
	const s = signer ?? carrier;
	if (s) return { id: s.id, name: s.name, known: true };
	if (ptr) return { id: "other", name: `A server at ${baseOf(ptr.toLowerCase())}`, known: false };
	return { id: "other", name: "A server we don't recognise", known: false };
}

/** The reverse DNS name to look up for an IP address (in-addr.arpa or ip6.arpa), or null for junk. */
export function ptrName(ip: string): string | null {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split(".").map(Number).some((n) => n > 255) ? null : `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
	if (!/^[0-9a-f:]+$/i.test(ip) || !ip.includes(":")) return null;
	const [head, tail = ""] = ip.toLowerCase().split("::");
	if (ip.split("::").length > 2) return null;
	const a = head ? head.split(":") : [];
	const b = tail ? tail.split(":") : [];
	const fill = ip.includes("::") ? 8 - a.length - b.length : 0;
	const groups = [...a, ...Array(Math.max(0, fill)).fill("0"), ...b];
	if (groups.length !== 8 || groups.some((g) => g.length > 4)) return null;
	return `${groups.map((g) => g.padStart(4, "0")).join("").split("").reverse().join(".")}.ip6.arpa`;
}

// --- What it all means --------------------------------------------------------------------------

/** One row as we keep it: the report's row plus who sent it. */
export interface StoredRow extends Row {
	sender: Sender;
	ptr?: string | null;
}

export type Verdict = "pass" | "warn" | "fail" | "info";

/** What one sender did, and what to do about it. Shaped like a check card (public/app.js card()). */
export interface SenderResult {
	id: string;
	/** What a "Mine" or "Not mine" label is saved against: the service id, or other:<name>, or "forwarded". */
	key: string;
	name: string;
	/** What its owner told us: it's theirs, it isn't, or nothing yet. */
	label: SenderLabel | null;
	known: boolean;
	messages: number;
	passed: number;
	dkimAligned: number;
	spfAligned: number;
	/** Messages a receiver quarantined or rejected because of your policy. */
	blocked: number;
	ips: { ip: string; ptr: string | null; messages: number; passed: number }[];
	/** The domains it signed with (d=) when they weren't yours. */
	foreignDkim: string[];
	/** The domains SPF was checked on (the envelope sender, not the From address), and whether each is yours. */
	spfDomains: { domain: string; yours: boolean }[];
	status: Verdict;
	title: string;
	summary: string;
	fix?: { steps: string[]; link?: { href: string; text: string } };
	why: string;
	found: string[];
}

export interface Analysis {
	domain: string;
	messages: number;
	passed: number;
	/** Whole percentages, rounded down so 99.6% doesn't show as 100%. */
	passRate: number;
	/** Mail from senders that are yours (everything but servers we think aren't), and how much of it passed. */
	own: { messages: number; passed: number; passRate: number };
	/** Emails from servers we don't recognise: either a service of yours that isn't set up in your DNS yet, or someone using your name. */
	others: number;
	/** Your own mail that failed only because someone forwarded it on (a forwarding rule or a mailing list). */
	forwarded: number;
	/** Mail sent from subdomains (the From address was shop.example.co.uk, not example.co.uk), busiest first. */
	subdomains: { domain: string; messages: number; passed: number }[];
	senders: SenderResult[];
	reporters: { org: string; reports: number; messages: number }[];
	policy: Policy | null;
	from: string | null;
	to: string | null;
	headline: string;
	line: string;
	counts: { fail: number; warn: number; pass: number; info: number };
}

/** "mine": the owner says this sender is theirs. "not": it isn't, so failing is fine. */
export type SenderLabel = "mine" | "not";

const pctOf = (n: number, of: number) => (of ? Math.floor((n / of) * 100) : 0);
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString("en-GB")} ${n === 1 ? one : many}`;

/** The plain-English verdict for one sender. */
function judge(s: Omit<SenderResult, "status" | "title" | "summary" | "fix" | "why" | "found">, domain: string): Pick<SenderResult, "status" | "title" | "summary" | "fix" | "why"> {
	const rate = s.passed / s.messages;
	const service = SERVICES.find((x) => x.id === s.id);
	const title = s.name;
	const dkimSteps = service?.dkim.length ? { steps: service.dkim, link: service.help ? { href: service.help, text: `${service.name.split(" /")[0]}'s own guide` } : undefined } : undefined;
	const why = "DMARC passes when DKIM or SPF passes for your own domain. DKIM is a signature added to each email; SPF is the list of servers allowed to send for you. Either one is enough, but DKIM survives forwarding, so it's the one to get right.";
	if (s.key === "forwarded") {
		return {
			status: "info", title,
			summary: `${plural(s.messages, "email")} you sent were passed on by someone's forwarding rule or a mailing list, which changed them so your signature no longer matched. That's normal, and it doesn't count against you.`,
			why: "When an email is forwarded, it leaves from the forwarder's server, so SPF fails, and if the forwarder edits it (a mailing list adds a footer) your DKIM signature breaks too. Receivers that know the forwarder usually still deliver it.",
		};
	}
	if (s.label === "not") {
		return { status: "info", title, summary: `You told us this isn't yours, so your DMARC policy is what stops it. ${plural(s.messages, "email")} in this period.`, why };
	}
	if (s.label === "mine" && !s.known && rate < 0.98) {
		return {
			status: "fail", title,
			summary: `You told us this is yours, and ${plural(s.messages - s.passed, "email")} from it failed. Have it send through your email service, or set up DKIM for ${domain} on it, before your policy gets stricter.`,
			fix: { steps: ["Find the email settings of the system that sends this mail (a website, shop, printer or app).", "Point it at your email service's SMTP server with a username and password, so it sends as you.", `Or, if it offers DKIM, add the record it gives you for ${domain}.`] },
			why,
		};
	}
	if (rate >= 0.98) {
		return { status: "pass", title, summary: `All good. ${pctOf(s.passed, s.messages)}% of ${plural(s.messages, "email")} passed DMARC${s.dkimAligned >= s.passed * 0.98 ? ", signed with your own DKIM" : ""}.`, why };
	}
	if (s.known && rate > 0) {
		const forwarded = service?.mailbox ? " The failures are most likely mail forwarded on by someone's forwarding rule or a mailing list, which changes the message." : "";
		return {
			status: "warn", title,
			summary: `Mostly working: ${pctOf(s.passed, s.messages)}% of ${plural(s.messages, "email")} passed.${forwarded} Keep an eye on it; if the failures grow, check every account you send from in ${s.name.split(" /")[0]} signs with DKIM.`,
			fix: dkimSteps, why,
		};
	}
	if (s.known && service?.mailbox) {
		return {
			status: "warn", title,
			summary: `${plural(s.messages, "email")} from ${s.name.split(" /")[0]} failed. If you use ${s.name.split(" /")[0]} for your own email, turn on DKIM for ${domain} there. If you don't, this is mail someone forwarded through it, and you can leave it failing.`,
			fix: dkimSteps, why,
		};
	}
	if (s.known) {
		const own = s.foreignDkim.length ? ` It signs with its own name (${s.foreignDkim.slice(0, 2).join(", ")}) instead of yours.` : " It isn't signing your mail with DKIM.";
		return {
			status: "fail", title,
			summary: `${plural(s.messages, "email")} sent through ${s.name} failed DMARC.${own} Set up DKIM for ${domain} in ${s.name}, or these emails will be blocked once your policy is stricter.`,
			fix: dkimSteps ?? { steps: [`Ask ${s.name} how to set up DKIM ("domain authentication") for ${domain}. They give you DNS records to add.`] }, why,
		};
	}
	if (s.messages >= 50) {
		return {
			status: "warn", title,
			summary: `${plural(s.messages, "email")} came from a server we don't recognise and failed. This is often one of your own services that was never added to your DNS records: a booking system, an app, a shop, website forms or notifications. Check whether it's yours before your policy gets stricter, or its email will go to spam or be refused too.`,
			fix: { steps: ["Look at the server names below: do you recognise the company, or something you signed up to?", `If it's yours, find its email settings and either send through your email service (an SMTP server you already use) or add the DKIM record it gives you for ${domain}, then mark it Mine.`, "If it isn't yours, mark it Not mine. Someone is using your name, and your DMARC policy is what stops their mail."] },
			why,
		};
	}
	return {
		status: "info", title,
		summary: `${plural(s.messages, "email")} from a server we don't recognise, and it failed. If it's one of your own services (an app, booking system or notifications) that you haven't set up in DNS, add it to your DNS records so it passes, and mark it Mine. If it isn't yours, mark it Not mine: your DMARC policy stops it.`,
		why,
	};
}

/** Adds up rows from any number of reports into one answer per sender. */
/**
 * Your own mail that only failed because it was forwarded: the receiver says so, or it carries a DKIM signature
 * from your domain that broke on the way (a mailing list footer, a forwarding rule).
 */
export function wasForwarded(r: Pick<Row, "dkim" | "spf" | "dkimAuth" | "reasons">, domain: string): boolean {
	if (r.dkim === "pass" || r.spf === "pass") return false;
	if ((r.reasons ?? []).some((x) => ["forwarded", "mailing_list", "trusted_forwarder"].includes(x))) return true;
	return r.dkimAuth.some((d) => (d.domain === domain || d.domain.endsWith(`.${domain}`)) && d.result !== "pass");
}

/** What a sender's mail is grouped and labelled under: forwarded mail, a named service, or other:<server name>. */
export function senderKey(r: Pick<StoredRow, "dkim" | "spf" | "dkimAuth" | "reasons" | "sender">, domain: string): string {
	if (wasForwarded(r, domain)) return "forwarded";
	return r.sender.id === "other" ? `other:${r.sender.name}` : r.sender.id;
}

/** Emails and passes per day for each sender, for the account's chart (a report counts on the day it ends). */
export function byDay(domain: string, reports: { end: string; rows: StoredRow[] }[]): { day: string; key: string; messages: number; passed: number }[] {
	const out = new Map<string, { day: string; key: string; messages: number; passed: number }>();
	for (const rep of reports) {
		const day = rep.end.slice(0, 10);
		if (!day) continue;
		for (const r of rep.rows) {
			const key = senderKey(r, domain);
			const id = `${day} ${key}`;
			const x = out.get(id) ?? { day, key, messages: 0, passed: 0 };
			x.messages += r.count;
			if (r.dkim === "pass" || r.spf === "pass") x.passed += r.count;
			out.set(id, x);
		}
	}
	return [...out.values()].sort((a, b) => a.day.localeCompare(b.day) || b.messages - a.messages);
}

export function analyse(domain: string, reports: { org: string; begin: string; end: string; policy: Policy; rows: StoredRow[] }[], labels: Map<string, SenderLabel> = new Map()): Analysis {
	const by = new Map<string, Omit<SenderResult, "status" | "title" | "summary" | "fix" | "why" | "found"> & { ipMap: Map<string, { ip: string; ptr: string | null; messages: number; passed: number }>; foreign: Set<string>; spf: Map<string, boolean> }>();
	const reporters = new Map<string, { org: string; reports: number; messages: number }>();
	let messages = 0;
	let passed = 0;
	const subs = new Map<string, { domain: string; messages: number; passed: number }>();
	let latest: { end: string; policy: Policy } | null = null;
	let from: string | null = null;
	let to: string | null = null;
	for (const rep of reports) {
		if (!latest || rep.end > latest.end) latest = { end: rep.end, policy: rep.policy };
		if (rep.begin && (!from || rep.begin < from)) from = rep.begin;
		if (rep.end && (!to || rep.end > to)) to = rep.end;
		const who = reporters.get(rep.org) ?? { org: rep.org, reports: 0, messages: 0 };
		who.reports++;
		reporters.set(rep.org, who);
		for (const r of rep.rows) {
			const ok = r.dkim === "pass" || r.spf === "pass";
			messages += r.count;
			who.messages += r.count;
			if (ok) passed += r.count;
			if (r.headerFrom && r.headerFrom !== domain && r.headerFrom.endsWith(`.${domain}`)) {
				const sub = subs.get(r.headerFrom) ?? { domain: r.headerFrom, messages: 0, passed: 0 };
				sub.messages += r.count;
				if (ok) sub.passed += r.count;
				subs.set(r.headerFrom, sub);
			}
			const key = senderKey(r, domain);
			const fwd = key === "forwarded";
			let s = by.get(key);
			if (!s) {
				s = { id: fwd ? "forwarded" : r.sender.id, key, name: fwd ? "Forwarded mail" : r.sender.name, label: labels.get(key) ?? null, known: fwd || r.sender.known, messages: 0, passed: 0, dkimAligned: 0, spfAligned: 0, blocked: 0, ips: [], foreignDkim: [], spfDomains: [], ipMap: new Map(), foreign: new Set(), spf: new Map() };
				by.set(key, s);
			}
			if (r.spfAuth?.domain) s.spf.set(r.spfAuth.domain, r.spfAuth.domain === domain || r.spfAuth.domain.endsWith(`.${domain}`));
			s.messages += r.count;
			if (ok) s.passed += r.count;
			if (r.dkim === "pass") s.dkimAligned += r.count;
			if (r.spf === "pass") s.spfAligned += r.count;
			if (r.disposition === "quarantine" || r.disposition === "reject") s.blocked += r.count;
			for (const d of r.dkimAuth) if (d.domain && d.result === "pass" && d.domain !== domain && !d.domain.endsWith(`.${domain}`)) s.foreign.add(d.domain);
			const ip = s.ipMap.get(r.ip) ?? { ip: r.ip, ptr: r.ptr ?? null, messages: 0, passed: 0 };
			ip.messages += r.count;
			if (ok) ip.passed += r.count;
			s.ipMap.set(r.ip, ip);
		}
	}
	const ORDER: Record<Verdict, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
	const senders: SenderResult[] = [...by.values()].map(({ ipMap, foreign, spf, ...s }) => {
		const base = { ...s, ips: [...ipMap.values()].sort((a, b) => b.messages - a.messages).slice(0, 50), foreignDkim: [...foreign].slice(0, 5),
			spfDomains: [...spf].slice(0, 5).map(([d, yours]) => ({ domain: d, yours })) };
		const verdict = judge(base, domain);
		const found = [
			`Emails: ${s.messages.toLocaleString("en-GB")}, passed DMARC: ${s.passed.toLocaleString("en-GB")}`,
			`DKIM matched your domain: ${s.dkimAligned.toLocaleString("en-GB")}; SPF matched your domain: ${s.spfAligned.toLocaleString("en-GB")}`,
			...(s.blocked ? [`Sent to spam or refused because of your policy: ${s.blocked.toLocaleString("en-GB")}`] : []),
			...(base.foreignDkim.length ? [`Signed by: ${base.foreignDkim.join(", ")}`] : []),
			// SPF is checked on the envelope sender: when that's the service's own domain, adding the service to your SPF record changes nothing.
			...(base.spfDomains.length ? [`SPF checked on: ${base.spfDomains.map((x) => `${x.domain}${x.yours ? " (yours)" : " (not yours, so your SPF record doesn't apply)"}`).join(", ")}`] : []),
			...base.ips.slice(0, 12).map((i) => `${i.ip}${i.ptr ? ` (${i.ptr})` : ""}: ${i.messages.toLocaleString("en-GB")} email${i.messages === 1 ? "" : "s"}, ${i.passed.toLocaleString("en-GB")} passed`),
			...(base.ips.length > 12 ? [`…and ${base.ips.length - 12} more servers`] : []),
		];
		return { ...base, ...verdict, found };
	}).sort((a, b) => ORDER[a.status] - ORDER[b.status] || b.messages - a.messages);
	const counts = { fail: 0, warn: 0, pass: 0, info: 0 };
	for (const s of senders) counts[s.status]++;
	const passRate = pctOf(passed, messages);
	const mine = senders.filter((s) => s.status !== "info");
	const ownMessages = mine.reduce((n, s) => n + s.messages, 0);
	const ownPassed = mine.reduce((n, s) => n + s.passed, 0);
	const own = { messages: ownMessages, passed: ownPassed, passRate: pctOf(ownPassed, ownMessages) };
	const forwarded = senders.find((s) => s.key === "forwarded")?.messages ?? 0;
	// Servers we don't recognise might be yours, so they're never waved through as "everything passes".
	const toCheck = senders.filter((s) => s.status === "info" && s.key !== "forwarded" && s.label !== "not").length;
	const headline = !messages ? "No email in these reports yet"
		: counts.fail ? `${plural(counts.fail, "sender")} to fix`
		: counts.warn ? "Nearly there"
		: toCheck ? `Your known senders pass. ${plural(toCheck, "server")} to check`
		: "Everything you send passes";
	const line = !messages ? "Reports usually start to arrive a day or two after you add the DMARC record."
		: `${passRate}% of ${plural(messages, "email")} sent as ${domain} passed DMARC, from ${plural(senders.length, "sender")}.`;
	return {
		domain, messages, passed, passRate, own, others: messages - ownMessages - forwarded, forwarded,
		subdomains: [...subs.values()].sort((a, b) => b.messages - a.messages).slice(0, 20), senders,
		reporters: [...reporters.values()].sort((a, b) => b.messages - a.messages),
		policy: latest?.policy ?? null, from, to, headline, line, counts,
	};
}

// --- The DMARC record, and stepping it up -------------------------------------------------------

/** A DMARC record's tags, in order (v first). Unknown or repeated tags keep their first value. */
export function parseDmarc(record: string): Map<string, string> {
	const tags = new Map<string, string>();
	for (const part of record.replace(/"\s*"/g, "").replace(/"/g, "").split(";")) {
		const i = part.indexOf("=");
		if (i < 1) continue;
		const k = part.slice(0, i).trim().toLowerCase();
		if (k && !tags.has(k)) tags.set(k, part.slice(i + 1).trim());
	}
	return tags;
}

/**
 * The record to paste for a policy: keeps their other tags (sp, adkim, ruf…) and any other report
 * addresses, adds ours to rua, and sets p and pct.
 */
export function dmarcRecord(current: string | null, report: string, p: string, pct = 100): string {
	const tags = current ? parseDmarc(current) : new Map<string, string>();
	const rua = (tags.get("rua") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
	const ours = `mailto:${report}`;
	if (!rua.some((r) => r.toLowerCase() === ours.toLowerCase())) rua.push(ours);
	const out: string[] = ["v=DMARC1", `p=${p}`];
	if (pct < 100) out.push(`pct=${pct}`);
	out.push(`rua=${rua.join(",")}`);
	for (const [k, v] of tags) if (!["v", "p", "pct", "rua"].includes(k)) out.push(`${k}=${v}`);
	return out.join("; ");
}

export interface Stage {
	key: string;
	/** What happens at this level, in plain words. */
	title: string;
	/** The same level in DMARC's own terms: "Policy: None", "Quarantine 25%" (Option A). */
	tech: string;
	p: string;
	pct: number;
	/** How long to stay before moving on. */
	weeks: number;
	what: string;
}

/** The suggested rollout for a new domain: watch first, then step up the share of failing mail that's held back. */
export const STAGES: Stage[] = [
	{ key: "none", title: "Monitor only", tech: "Policy: None", p: "none", pct: 100, weeks: 4, what: "Nothing is blocked. Reports show who sends as you, so you can fix your own services first." },
	{ key: "q25", title: "25% unauthenticated to spam", tech: "Quarantine 25%", p: "quarantine", pct: 25, weeks: 2, what: "A quarter of the mail that fails DMARC goes to the spam folder. That's anyone pretending to be you, and any service of yours whose DNS records aren't set up yet, so fix those first." },
	{ key: "q50", title: "50% unauthenticated to spam", tech: "Quarantine 50%", p: "quarantine", pct: 50, weeks: 2, what: "Half of the mail that fails DMARC goes to the spam folder." },
	{ key: "q100", title: "Send unauthenticated to spam", tech: "Policy: Quarantine", p: "quarantine", pct: 100, weeks: 2, what: "All mail that fails DMARC goes to the spam folder." },
	{ key: "reject", title: "Block unauthenticated mail", tech: "Policy: Reject", p: "reject", pct: 100, weeks: 0, what: "Mail that fails DMARC is refused outright. Nobody else can send email as you, and any new service you add must be set up in your DNS before it can." },
];

/** Which step a policy is on. */
export function stageOf(p: string | undefined, pct: number | undefined): number {
	const share = pct ?? 100;
	if (p === "reject") return 4;
	if (p === "quarantine") return share <= 25 ? 1 : share <= 50 ? 2 : 3;
	return 0;
}

export interface RolloutStep extends Stage {
	/** "skipped": an earlier step we never saw the domain on (it went straight past it). */
	state: "done" | "skipped" | "now" | "next" | "later";
	/** When this step can start (for the current one, when it started). */
	date: string | null;
	record: string;
}

export interface Rollout {
	current: number;
	steps: RolloutStep[];
	/** Whether the next step can be taken now, and why not when it can't. */
	ready: boolean;
	waitingFor: string[];
	nextDate: string | null;
	nextRecord: string | null;
}

const addWeeks = (iso: string, w: number) => new Date(Date.parse(iso) + w * 7 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
const day = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "long", timeZone: "UTC" });

/**
 * Where a domain is on the way to p=reject. `since` is when we first saw its current policy;
 * `recent` is the last two weeks of reports. The next step goes green only when the time is up
 * and every service that's really yours passes.
 */
export function rollout(opts: { record: string | null; report: string; since: string | null; recent: Analysis; now?: Date; seen?: number[] }): Rollout {
	const tags = opts.record ? parseDmarc(opts.record) : null;
	const pct = Number(tags?.get("pct"));
	const current = tags ? stageOf(tags.get("p")?.toLowerCase(), Number.isFinite(pct) && tags.has("pct") ? pct : 100) : -1;
	const now = (opts.now ?? new Date()).toISOString().replace(/\.\d{3}Z$/, "Z");
	const since = opts.since ?? now;
	// The current step started `since`; each later one follows after the weeks of the one before.
	// With no record yet, step one starts today.
	const first = Math.max(current, 0);
	let date = current >= 0 ? since : now;
	const steps: RolloutStep[] = STAGES.map((s, i) => {
		let d: string | null = null;
		if (i === first) d = date;
		else if (i > first) d = date = addWeeks(date, STAGES[i - 1].weeks);
		return {
			...s,
			state: i < current ? (opts.seen && !opts.seen.includes(i) ? "skipped" : "done") : i === current ? "now" : i === current + 1 ? "next" : "later",
			date: d,
			record: dmarcRecord(opts.record, opts.report, s.p, s.pct),
		};
	});
	const waitingFor: string[] = [];
	const next = steps[current + 1];
	let nextDate: string | null = null;
	if (current === -1) {
		waitingFor.push("Add the DMARC record above to start watching.");
	} else if (next) {
		nextDate = addWeeks(since, STAGES[current].weeks);
		if (nextDate > now) waitingFor.push(`Give this step until ${day(nextDate)} (${plural(STAGES[current].weeks, "week")} in all), so a full cycle of reports comes in.`);
		// Not for a step that started under two weeks ago: a new domain hasn't had time for any.
		if (!opts.recent.messages && addWeeks(since, 2) <= now) waitingFor.push("We haven't had any reports in the last two weeks. Check the DMARC record includes your report address.");
		// Services that are yours: any we can name that send mail for you, plus anything that sometimes passes.
		// Mailbox providers (Gmail, Outlook…) also carry forwarded mail, which can fail however well you've set up, so they get more leeway.
		for (const s of opts.recent.senders) {
			if (s.key === "forwarded" || s.label === "not") continue;
			const mailbox = !!SERVICES.find((x) => x.id === s.id)?.mailbox;
			const yours = s.label === "mine" || (s.known && !mailbox) || s.passed > 0;
			if (yours && s.passed / s.messages < (mailbox ? 0.9 : 0.95)) waitingFor.push(`${s.name} is still failing (${pctOf(s.passed, s.messages)}% passed). Fix that first.`);
		}
	}
	return {
		current, steps, ready: !!next && current >= 0 && !waitingFor.length, waitingFor,
		nextDate, nextRecord: next ? next.record : null,
	};
}

// --- Alerts -------------------------------------------------------------------------------------
// Three emails a DMARC domain can send, each with its own switch. The daily job (src/cron.ts) looks at
// each domain once a day.

export type DmarcAlert = "new" | "failing" | "silent" | "tls";
export const DMARC_ALERTS: [DmarcAlert, string, string][] = [
	["new", "New sender", "Someone new starts sending email as this domain"],
	["failing", "Your mail failing", "A sender that's yours starts failing DMARC"],
	["silent", "Reports stopped", "No reports for 3 days, which usually means the DMARC record changed"],
	["tls", "Encryption failing", "Mail servers report that email to you couldn't be sent encrypted (from TLS reports)"],
];

/**
 * Which alerts are on (all of them unless switched off). `mineOnly` (25 Oct 2026, off unless switched on): the
 * failing alert only covers senders marked Mine, not every service we recognise.
 */
export function alertSettings(saved: string | null | undefined): Record<DmarcAlert, boolean> & { mineOnly: boolean } {
	let given: Record<string, unknown> = {};
	try { given = saved ? JSON.parse(saved) : {}; } catch { /* the defaults */ }
	return { new: given.new !== false, failing: given.failing !== false, silent: given.silent !== false, tls: given.tls !== false, mineOnly: given.mineOnly === true };
}

/** What the alerts already told someone, so each thing is only said once. */
export interface AlertState {
	/** Senders already announced as new. */
	known: string[];
	/** When each failing sender was last emailed about. */
	failing: Record<string, string>;
	/** When we said reports had stopped (cleared once they come back). */
	silentAt: string | null;
	/** When we last said mail to the domain wasn't encrypted (TLS reports). */
	tlsAt?: string | null;
}

export function alertState(saved: string | null | undefined): AlertState {
	try {
		const s = saved ? JSON.parse(saved) : {};
		return { known: Array.isArray(s.known) ? s.known.slice(-200) : [], failing: s.failing && typeof s.failing === "object" ? s.failing : {}, silentAt: typeof s.silentAt === "string" ? s.silentAt : null, tlsAt: typeof s.tlsAt === "string" ? s.tlsAt : null };
	} catch {
		return { known: [], failing: {}, silentAt: null };
	}
}

export interface DueAlert { kind: DmarcAlert; subject: string; text: string }

/**
 * The alerts due for one domain today. `recent` is the last 3 days of reports, `before` the 30 days before
 * that; `state` is what we've already said. Returns the emails to send and the state to keep.
 */
export function dmarcAlerts(opts: { domain: string; recent: Analysis; before: Analysis; state: AlertState; on: Record<DmarcAlert, boolean> & { mineOnly?: boolean }; link: string; now: Date }): { due: DueAlert[]; state: AlertState } {
	const { domain, recent, before, on, link } = opts;
	const now = opts.now.toISOString().replace(/\.\d{3}Z$/, "Z");
	const state: AlertState = { known: [...opts.state.known], failing: { ...opts.state.failing }, silentAt: opts.state.silentAt, tlsAt: opts.state.tlsAt ?? null };
	const due: DueAlert[] = [];
	const foot = `See everything: ${link}\n\nYou get this email because this alert is on for ${domain} in DMARC Reports. You can switch it off in the domain's settings.`;

	// New senders: in the last 3 days, never in the 30 before, not forwarded mail and not marked "not mine".
	// Everyone seen before the first run counts as known, so switching alerts on doesn't announce the lot.
	const first = !opts.state.known.length;
	for (const s of before.senders) if (!state.known.includes(s.key)) state.known.push(s.key);
	const fresh = recent.senders.filter((s) => s.key !== "forwarded" && s.label !== "not" && !state.known.includes(s.key) && s.messages >= 2);
	for (const s of recent.senders) if (!state.known.includes(s.key)) state.known.push(s.key);
	state.known = state.known.slice(-200);
	if (on.new && fresh.length && !first) {
		const lines = fresh.slice(0, 5).map((s) => `- ${s.name}: ${plural(s.messages, "email")}, ${pctOf(s.passed, s.messages)}% passed DMARC.`);
		due.push({
			kind: "new",
			subject: fresh.length === 1 ? `${domain}: a new sender, ${fresh[0].name}` : `${domain}: ${fresh.length} new senders`,
			text: [`Hello,`, `${fresh.length === 1 ? "Something new has" : "Some new servers have"} started sending email as ${domain}:`, lines.join("\n"),
				"If it's yours, mark it Mine on the domain's page and we'll tell you how to make it pass. If it isn't, mark it Not mine: your DMARC policy is what stops it.", foot].join("\n\n"),
		});
	}

	// Your own mail failing: a sender that's yours under 95% in the last 3 days, at most once a week each.
	// Yours: marked Mine, or a service we recognise that isn't marked Not mine (unless they chose Mine only).
	const week = 7 * 86_400_000;
	const failing = recent.senders.filter((s) => s.key !== "forwarded" && s.label !== "not" && (s.label === "mine" || (!on.mineOnly && s.known && s.status !== "info")) && s.messages >= 5 && s.passed / s.messages < 0.95
		&& !(state.failing[s.key] && Date.parse(now) - Date.parse(state.failing[s.key]) < week));
	for (const s of failing) state.failing[s.key] = now;
	if (on.failing && failing.length) {
		const s = failing[0];
		due.push({
			kind: "failing",
			subject: failing.length === 1 ? `${domain}: email from ${s.name} is failing DMARC` : `${domain}: ${failing.length} of your senders are failing DMARC`,
			text: [`Hello,`, failing.map((x) => `- ${x.name}: ${pctOf(x.passed, x.messages)}% of ${plural(x.messages, "email")} passed in the last 3 days. ${x.summary}`).join("\n"),
				...(s.fix ? [`To fix ${s.name}:\n${s.fix.steps.map((step, i) => `${i + 1}. ${step}`).join("\n")}`] : []),
				recent.policy && recent.policy.p !== "none" ? `Your policy is p=${recent.policy.p}, so failing mail is ${recent.policy.p === "reject" ? "being refused" : "going to spam"} right now.` : "", foot].filter(Boolean).join("\n\n"),
		});
	}

	// Reports stopped: some in the 30 days before, none in the last 3. Said once, until they come back.
	if (recent.messages) state.silentAt = null;
	else if (before.messages && !state.silentAt) {
		state.silentAt = now;
		if (on.silent) {
			due.push({
				kind: "silent",
				subject: `${domain}: DMARC reports have stopped`,
				text: [`Hello,`, `We haven't had a DMARC report for ${domain} for 3 days, and we usually get them every day. That usually means the DMARC record was changed or removed, so mail providers no longer know where to send them.`,
					"Check the _dmarc record for the domain still includes your report address. The domain's page shows the exact record to use.", foot].join("\n\n"),
			});
		}
	}
	return { due, state };
}

// --- Every row, filtered (25 Oct 2026) ----------------------------------------------------------
// The rows behind the analysis, one per sending server per report, for the domain page's "Every row"
// box and a filtered CSV. Filters: the DMARC result, the sender, the mail provider that sent the report,
// a DKIM selector and what the receiver did with the mail.

export interface RowFilter {
	result?: "pass" | "fail" | "forwarded";
	sender?: string;
	org?: string;
	selector?: string;
	disposition?: string;
}

/** The filters from a query string; anything unexpected is left out. */
export function rowFilter(q: URLSearchParams): RowFilter {
	const f: RowFilter = {};
	const result = q.get("result");
	if (result === "pass" || result === "fail" || result === "forwarded") f.result = result;
	for (const k of ["sender", "org", "selector"] as const) {
		const v = (q.get(k) ?? "").trim().slice(0, 200);
		if (v) f[k] = v;
	}
	const d = (q.get("disposition") ?? "").toLowerCase();
	if (["none", "quarantine", "reject"].includes(d)) f.disposition = d;
	return f;
}

export interface ViewRow {
	end: string;
	org: string;
	ip: string;
	ptr: string | null;
	sender: string;
	senderKey: string;
	count: number;
	/** DMARC's verdict for the row, with forwarded mail apart. */
	result: "pass" | "fail" | "forwarded";
	dkim: string;
	spf: string;
	disposition: string;
	headerFrom: string;
	dkimAuth: { domain: string; selector: string; result: string }[];
	spfAuth: { domain: string; result: string } | null;
}

export interface RowsView {
	/** Rows and emails that match the filters, and how many of those emails passed. */
	matched: number;
	messages: number;
	passed: number;
	rows: ViewRow[];
	/** What each filter can be set to in this period, busiest first, with the emails behind each. */
	options: {
		senders: { key: string; name: string; messages: number }[];
		orgs: { name: string; messages: number }[];
		selectors: { name: string; messages: number }[];
		dispositions: { name: string; messages: number }[];
	};
}

/** Filters a period's rows, newest report first, and pages through them. */
export function filterRows(domain: string, reports: { org: string; end: string; rows: StoredRow[] }[], f: RowFilter, offset = 0, limit = 100): RowsView {
	const all: ViewRow[] = [];
	for (const rep of reports) {
		for (const r of rep.rows) {
			const key = senderKey(r, domain);
			all.push({
				end: rep.end, org: rep.org, ip: r.ip, ptr: r.ptr ?? null, sender: r.sender.name, senderKey: key, count: r.count,
				result: r.dkim === "pass" || r.spf === "pass" ? "pass" : key === "forwarded" ? "forwarded" : "fail",
				dkim: r.dkim, spf: r.spf, disposition: r.disposition, headerFrom: r.headerFrom, dkimAuth: r.dkimAuth, spfAuth: r.spfAuth,
			});
		}
	}
	all.sort((a, b) => b.end.localeCompare(a.end) || b.count - a.count);
	const tally = (pick: (r: ViewRow) => string[]) => {
		const m = new Map<string, number>();
		for (const r of all) for (const k of new Set(pick(r))) if (k) m.set(k, (m.get(k) ?? 0) + r.count);
		return [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 100).map(([name, messages]) => ({ name, messages }));
	};
	const names = new Map(all.map((r) => [r.senderKey, r.senderKey === "forwarded" ? "Forwarded mail" : r.sender]));
	const shown = all.filter((r) => (!f.result || r.result === f.result) && (!f.sender || r.senderKey === f.sender) && (!f.org || r.org === f.org)
		&& (!f.selector || r.dkimAuth.some((d) => d.selector === f.selector)) && (!f.disposition || r.disposition === f.disposition));
	return {
		matched: shown.length,
		messages: shown.reduce((n, r) => n + r.count, 0),
		passed: shown.reduce((n, r) => n + (r.result === "pass" ? r.count : 0), 0),
		rows: shown.slice(offset, offset + limit),
		options: {
			senders: tally((r) => [r.senderKey]).map(({ name, messages }) => ({ key: name, name: names.get(name) ?? name, messages })),
			orgs: tally((r) => [r.org]),
			selectors: tally((r) => r.dkimAuth.map((d) => d.selector)),
			dispositions: tally((r) => [r.disposition]),
		},
	};
}

// --- Sharing, export and the weekly email ---------------------------------------------------------

/** One CSV field: quoted when it needs to be, and never starting with = + - @ (a spreadsheet would run it). */
export function csvField(v: unknown): string {
	let s = v == null ? "" : String(v);
	if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
	return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const CSV_HEAD = ["Report from", "Reporter", "Server IP", "Reverse DNS", "Sender", "Emails", "DMARC", "DKIM aligned", "SPF aligned", "What the receiver did", "From domain", "DKIM signatures", "SPF domain"];

/** One report row as a CSV line (dates as YYYY-MM-DD). */
export function csvRow(r: { end: string; org: string; ip: string; ptr: string | null; sender: string; count: number; dkim: string; spf: string; disposition: string; headerFrom: string; dkimAuth: { domain: string; selector: string; result: string }[]; spfAuth: { domain: string; result: string } | null }): string {
	return [r.end.slice(0, 10), r.org, r.ip, r.ptr ?? "", r.sender, r.count, r.dkim === "pass" || r.spf === "pass" ? "pass" : "fail", r.dkim, r.spf, r.disposition, r.headerFrom,
		r.dkimAuth.map((d) => `${d.domain} (${d.selector || "?"}): ${d.result}`).join("; "), r.spfAuth ? `${r.spfAuth.domain}: ${r.spfAuth.result}` : ""].map(csvField).join(",");
}

/** The weekly summary: how your own mail did, anything to fix, and where the rollout is. */
export function weeklyEmail(domain: string, a: Analysis, r: Rollout | null, link: string): { subject: string; text: string } {
	const own = a.own.messages ? a.own : null;
	const fix = a.senders.filter((s) => s.status === "fail" || s.status === "warn");
	const yours = a.senders.filter((s) => s.status === "pass");
	const step = r && r.current >= 0 ? STAGES[r.current] : null;
	return {
		subject: !a.messages ? `${domain}: no DMARC reports this week` : `${domain}: ${own ? `${own.passRate}% of your mail passed` : `${a.passRate}% passed`} this week${fix.length ? `, ${plural(fix.length, "sender")} to fix` : ""}`,
		text: [
			"Hello,",
			!a.messages ? "No reports came in for this domain in the last week. If that's unexpected, check your DMARC record still includes your report address."
				: [
					own ? `Your mail: ${own.passRate}% of ${plural(own.messages, "email")} passed DMARC.` : `${a.passRate}% of ${plural(a.messages, "email")} passed DMARC.`,
					a.forwarded ? `Forwarded on by others: ${plural(a.forwarded, "email")} (normal, and not counted against you).` : "",
					a.others ? `From servers we don't recognise: ${plural(a.others, "email")}${a.policy && a.policy.p !== "none" ? `, ${a.policy.p === "reject" ? "refused" : "sent to spam"} by your policy` : ""}. If any of them are services of yours, add them to your DNS records.` : "",
				].filter(Boolean).join("\n"),
			fix.length ? `To fix:\n${fix.slice(0, 8).map((s) => `- ${s.name}: ${s.summary}`).join("\n")}` : "",
			yours.length ? `Passing:\n${yours.slice(0, 8).map((s) => `- ${s.name}: ${plural(s.messages, "email")}`).join("\n")}` : "",
			step ? `DMARC enforcement level: Level ${r!.current + 1} of ${STAGES.length}, ${step.tech} (${step.title.toLowerCase()}).${r && r.ready && r.nextRecord ? ` You're ready for the next step. Change your DMARC record to:\n${r.nextRecord}` : r && r.current === STAGES.length - 1 ? " That's the last step: mail that fails DMARC is refused, so set up any new service in your DNS before it sends." : ""}` : "",
			`See everything: ${link}`,
			"You get this email because the weekly summary is on for this domain in DMARC Reports. You can switch it off in the domain's settings.",
		].filter(Boolean).join("\n\n"),
	};
}
