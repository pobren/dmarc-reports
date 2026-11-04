// Looking things up in DNS, and the steps to add a record at the company that runs a domain's DNS.
// No database here; dohResolver() is the only part that uses the network.

/** One DNS record to add or change. `name` is relative to the domain: "@" means the domain itself. */
export interface DnsRecord {
	type: string;
	name: string;
	value: string;
	/** "add" a new record, or "edit" the one that's there. */
	action: "add" | "edit";
	priority?: number;
}

export interface Company {
	id: string;
	name: string;
}

export interface Answer {
	/** 0 found (even if empty), 3 no such name, -1 the look-up service failed, anything else a DNS problem. */
	status: number;
	/** The answers of the type asked for, as DNS over HTTPS gives them. */
	data: string[];
	/** True when the answer was DNSSEC-validated. */
	secure?: boolean;
}

export type Resolve = (name: string, type: string) => Promise<Answer>;

const TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

/** Looks names up with Cloudflare's DNS over HTTPS, remembering each answer for the rest of the request. */
export function dohResolver(fetcher: typeof fetch = fetch): Resolve {
	const cache = new Map<string, Promise<Answer>>();
	return (name, type) => {
		const key = `${name}|${type}`;
		let hit = cache.get(key);
		if (!hit) {
			hit = (async (): Promise<Answer> => {
				try {
					const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&do=1`;
					const res = await fetcher(url, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) });
					if (!res.ok) return { status: -1, data: [] };
					const body = (await res.json()) as { Status: number; AD?: boolean; Answer?: { type: number; data: string }[] };
					return { status: body.Status, secure: !!body.AD, data: (body.Answer ?? []).filter((a) => a.type === TYPES[type]).map((a) => a.data) };
				} catch {
					return { status: -1, data: [] };
				}
			})();
			cache.set(key, hit);
		}
		return hit;
	};
}

/** The domain from whatever was typed: "https://www.Example.com/page", "me@example.com", "example.com.". */
export function cleanDomain(input: unknown): string | null {
	let s = typeof input === "string" ? input.trim().toLowerCase() : "";
	if (!s) return null;
	if (s.includes("@") && !s.includes("/")) s = s.split("@").pop()!;
	s = s.replace(/^[a-z]+:\/\//, "").split(/[/?#:]/)[0].replace(/\.$/, "");
	try {
		s = new URL(`http://${s}`).hostname; // turns accented names into their xn-- form
	} catch {
		return null;
	}
	if (s.length > 253 || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(s)) return null;
	return s;
}

/** DNS over HTTPS gives TXT data as one or more quoted strings; join them into the record's value. */
export function joinTxt(data: string): string {
	const parts = data.match(/"((?:[^"\\]|\\.)*)"/g);
	if (!parts) return data;
	return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}

// -- Who runs the DNS ------------------------------------------------------

interface DnsHost extends Company {
	ns: RegExp;
	/** Where to change records. */
	where?: string;
	/** How to reach the DNS records from the control panel's front page, in the panel's own words. */
	menu?: string[];
	/** What the button for a new record is called. */
	add?: string;
	/** True when the panel wants the Name left empty for the domain itself, rather than "@". */
	blankRoot?: boolean;
}

const DNS_HOSTS: DnsHost[] = [
	{ id: "cloudflare", name: "Cloudflare", ns: /\.ns\.cloudflare\.com$/, where: "https://dash.cloudflare.com/", menu: ["Select your domain and open DNS › Records."], add: "Add record" },
	{ id: "godaddy", name: "GoDaddy", ns: /\.domaincontrol\.com$/, where: "https://dcc.godaddy.com/control/portfolio", menu: ["In Domain Portfolio, select your domain.", "Open the DNS tab, then DNS Records."], add: "Add New Record" },
	{ id: "namecheap", name: "Namecheap", ns: /\.registrar-servers\.com$/, where: "https://ap.www.namecheap.com/domains/list/", menu: ["In Domain List, click Manage next to your domain.", "Open the Advanced DNS tab and find Host Records."], add: "Add New Record" },
	{ id: "123reg", name: "123 Reg", ns: /\.123-reg\.co\.uk$/, where: "https://www.123-reg.co.uk/secure/", menu: ["Open your domain from the control panel.", "Choose Manage DNS, then the Advanced DNS tab."], add: "Add new entry" },
	{ id: "ionos", name: "IONOS", ns: /\.ui-dns\.(com|org|biz|de)$/, where: "https://my.ionos.co.uk/domains", menu: ["In Domains & SSL, click your domain.", "Open the DNS tab."], add: "Add record" },
	{ id: "fasthosts", name: "Fasthosts", ns: /\.fasthosts\.(co\.uk|net\.uk)$/, where: "https://admin.fasthosts.co.uk/", menu: ["Open Domain Names and select your domain.", "Open DNS settings, then Advanced DNS records."], add: "Add new record" },
	{ id: "route53", name: "Amazon Route 53", ns: /\.awsdns-\d+\./, where: "https://console.aws.amazon.com/route53/", menu: ["Open Hosted zones and choose your domain."], add: "Create record", blankRoot: true },
	{ id: "squarespace", name: "Squarespace Domains", ns: /\.(googledomains\.com|squarespacedns\.com)$/, where: "https://account.squarespace.com/domains", menu: ["Choose your domain.", "Open DNS, then DNS settings, and scroll to Custom records."], add: "Add record" },
	{ id: "google-cloud", name: "Google Cloud DNS", ns: /\.googledomains\.com$|^ns-cloud-/, where: "https://console.cloud.google.com/net-services/dns", menu: ["Open Cloud DNS and choose your domain's zone."], add: "Add standard", blankRoot: true },
	{ id: "hover", name: "Hover", ns: /\.hover\.com$/, where: "https://www.hover.com/control_panel", menu: ["Choose your domain.", "Open the DNS tab."], add: "Add a record" },
	{ id: "gandi", name: "Gandi", ns: /\.gandi\.net$/, where: "https://admin.gandi.net/", menu: ["Open Domain and choose your domain.", "Open the DNS records tab."], add: "Add record" },
	{ id: "ovh", name: "OVHcloud", ns: /\.ovh\.(net|ca)$/, where: "https://www.ovh.com/manager/", menu: ["Open Web Cloud › Domain names and choose your domain.", "Open the DNS zone tab."], add: "Add an entry", blankRoot: true },
	{ id: "digitalocean", name: "DigitalOcean", ns: /\.digitalocean\.com$/, where: "https://cloud.digitalocean.com/networking/domains", menu: ["Open Networking › Domains and choose your domain."], add: "Create Record" },
	{ id: "vercel", name: "Vercel", ns: /\.vercel-dns\.com$/, where: "https://vercel.com/dashboard/domains", menu: ["Open Domains and choose your domain.", "Scroll to DNS Records."], add: "Add" },
	{ id: "netlify", name: "Netlify", ns: /netlify/, where: "https://app.netlify.com/teams/", menu: ["Open Domains and choose your domain.", "Find DNS records."], add: "Add new record" },
	{ id: "ns1", name: "NS1", ns: /\.nsone\.net$/, menu: ["Open Zones and choose your domain."], add: "Add record" },
	{ id: "wix", name: "Wix", ns: /\.wixdns\.net$/, where: "https://manage.wix.com/account/domains", menu: ["Click the ⋯ menu next to your domain.", "Choose Manage DNS Records."], add: "Add Record" },
	{ id: "krystal", name: "Krystal", ns: /\.krystal\.(co\.uk|uk)$/, where: "https://krystal.uk/client/", menu: ["Open Domains and choose your domain.", "Open Manage DNS."], add: "Add record" },
	{ id: "porkbun", name: "Porkbun", ns: /\.porkbun\.com$/, where: "https://porkbun.com/account/domainsSpeedy", menu: ["Find your domain and click DNS under its name."], add: "Add" },
	{ id: "dnsimple", name: "DNSimple", ns: /\.dnsimple\.com$/, where: "https://dnsimple.com/dashboard", menu: ["Choose your domain.", "Open DNS, then Manage records."], add: "Add record" },
	{ id: "hostinger", name: "Hostinger", ns: /\.dns-parking\.com$|hostinger/, where: "https://hpanel.hostinger.com/domains", menu: ["Click Manage next to your domain.", "Open DNS / Nameservers."], add: "Add Record" },
	{ id: "tsohost", name: "TSOHost", ns: /\.tsohost\.co\.uk$/, where: "https://my.tsohost.com/", menu: ["Open Domains and choose your domain.", "Open DNS management."], add: "Add record" },
];

export function dnsHostFor(nameservers: string[]): DnsHost | null {
	for (const ns of nameservers) {
		const n = ns.toLowerCase().replace(/\.$/, "");
		const host = DNS_HOSTS.find((h) => h.ns.test(n));
		if (host) return host;
	}
	return null;
}

// -- Steps to add a record ---------------------------------------------------

/** "Name" as most DNS hosts want it, with a note for the ones that want the whole name. */
function nameHint(rec: DnsRecord, domain: string): string {
	if (rec.name === "@") return `Name / Host: @, meaning ${domain} itself. Some providers want this left blank instead.`;
	return `Name / Host: ${rec.name}. If your provider doesn't add .${domain} automatically, enter ${rec.name}.${domain}.`;
}

export function recordSteps(host: Company | null, domain: string, records: DnsRecord[]): string[] {
	const h = host ? DNS_HOSTS.find((x) => x.id === host.id) : undefined;
	const steps: string[] = [];
	if (h?.menu) {
		// "Select your domain." reads better with the domain's name in it.
		steps.push(`Sign in to ${h.name}${h.where ? ` at ${h.where.replace(/^https:\/\//, "").replace(/\/$/, "")}` : ""}.`, ...h.menu.map((m) => m.replace("your domain", domain)));
	} else if (h) {
		steps.push(`Sign in to ${h.name}${h.where ? ` (${h.where})` : ""}.`, "Open the domain's DNS settings (often called DNS Management, DNS Zone Editor or Advanced DNS).");
	} else {
		steps.push(`Sign in to the company that runs the DNS for ${domain}. This is usually where you bought the domain.`, "Open the domain's DNS settings (often called DNS Management, DNS Zone Editor or Advanced DNS).");
	}
	const add = h?.add ?? "Add Record";
	for (const rec of records) {
		steps.push(rec.action === "edit"
			? `Find the ${rec.type} record starting with ${rec.value.split(/\s/)[0]} and press Edit. Change it to the content below and save.`
			: `Press ${add}, choose ${rec.type} as the type, then enter the name and content below.${rec.priority !== undefined ? ` Set priority to ${rec.priority}.` : ""}`);
		steps.push(h?.menu ? hostNameHint(h, rec, domain) : nameHint(rec, domain));
	}
	const save = records.some((rec) => rec.action === "add") ? "Save. " : "";
	if (h?.id === "cloudflare") steps.push(`${save}Changes take effect globally within 5 minutes.`);
	else steps.push(`${save}Changes usually show within an hour, but can take up to 48 hours.`);
	steps.push("Come back here and press Check again.");
	return steps;
}

/** The Name field as this particular control panel wants it. */
function hostNameHint(h: DnsHost, rec: DnsRecord, domain: string): string {
	if (rec.name === "@") return h.blankRoot ? `Name / Host: leave it empty. In ${h.name}, an empty name means the domain itself (${domain}).` : `Name / Host: @ (${h.name} reads it as ${domain} itself).`;
	return `Name / Host: ${rec.name} (${h.name} automatically adds .${domain}).`;
}
