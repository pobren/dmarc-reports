// The pure parts of the `npx @mrpwob/dmarc-reports` installer: names, the command line, the token's permissions,
// the release manifest and the Worker upload metadata. No network calls here (see run.ts), so it can be tested.

/** Names of what we create on the person's account. Fixed, so running it again finds the same things. */
export const SCRIPT = "dmarc-reports";
export const DATABASE = "dmarc-reports";
/** With a domain, the app lives at <subdomain>.<domain>. */
export const SUBDOMAIN = "dmarc";
/** The report address's part before the @. */
export const REPORT_USER = "dmarc-reports";
export const CRON = "*/30 * * * *";

export const LOCATIONS = {
	weur: "Western Europe",
	eeur: "Eastern Europe",
	enam: "Eastern North America",
	wnam: "Western North America",
	apac: "Asia-Pacific",
	oc: "Oceania",
} as const;
export type Location = keyof typeof LOCATIONS;

export type Command = "setup" | "update" | "help" | "version";

export interface Options {
	command: Command;
	account?: string;
	/** The domain for the app's address and the report address, or "" to try it on workers.dev. */
	domain?: string;
	subdomain?: string;
	location?: string;
	yes: boolean;
	force: boolean;
}

export class UsageError extends Error {}

const VALUE_FLAGS = new Set(["account", "domain", "subdomain", "location"]);

export function parseArgs(argv: string[]): Options {
	const opts: Options = { command: "help", yes: false, force: false };
	const rest = [...argv];
	const first = rest[0];
	if (first && !first.startsWith("-")) {
		rest.shift();
		if (first === "setup" || first === "install") opts.command = "setup";
		else if (first === "update" || first === "upgrade") opts.command = "update";
		else if (first === "help") opts.command = "help";
		else if (first === "version") opts.command = "version";
		else throw new UsageError(`"${first}" isn't a dmarc-reports command. Try: npx @mrpwob/dmarc-reports setup, or npx @mrpwob/dmarc-reports update.`);
	}
	while (rest.length) {
		const arg = rest.shift()!;
		if (arg === "-h" || arg === "--help") { opts.command = "help"; continue; }
		if (arg === "-v" || arg === "--version") { opts.command = "version"; continue; }
		if (arg === "-y" || arg === "--yes") { opts.yes = true; continue; }
		if (arg === "--force") { opts.force = true; continue; }
		if (arg === "--trial") { opts.domain = ""; continue; }
		if (arg === "--token" || arg.startsWith("--token=")) {
			throw new UsageError("Please don't put your token on the command line, where it's saved in your shell history. Set CLOUDFLARE_API_TOKEN, or paste it when asked.");
		}
		const m = /^--([a-z]+)(?:=(.*))?$/.exec(arg);
		if (!m || !VALUE_FLAGS.has(m[1])) throw new UsageError(`Unknown option ${arg}. Run npx @mrpwob/dmarc-reports help to see the options.`);
		const value = m[2] ?? rest.shift();
		if (value === undefined || value.startsWith("--")) throw new UsageError(`--${m[1]} needs a value.`);
		(opts as unknown as Record<string, string>)[m[1]] = value.trim();
	}
	return opts;
}

/** Permissions the Cloudflare API token needs, as the dashboard names them on "Create Custom Token". */
export const TOKEN_PERMISSIONS: { group: "Account" | "Zone"; name: string; level: "Read" | "Edit" | "Admin" }[] = [
	{ group: "Account", name: "Account Settings", level: "Read" },
	{ group: "Account", name: "Workers", level: "Admin" },
	{ group: "Account", name: "D1", level: "Edit" },
	{ group: "Zone", name: "Zone", level: "Read" },
	{ group: "Zone", name: "DNS", level: "Edit" },
	{ group: "Zone", name: "Workers Routes", level: "Edit" },
	{ group: "Zone", name: "Email Routing Rules", level: "Edit" },
];

export const TOKENS_PAGE = "https://dash.cloudflare.com/profile/api-tokens";

export function tokenHelp(): string {
	const line = (p: (typeof TOKEN_PERMISSIONS)[number]) => `    ${p.group.padEnd(9)}${p.name}: ${p.level}`;
	return [
		`  Make one at ${TOKENS_PAGE}: Create Token, then "Create Custom Token", with:`,
		...TOKEN_PERMISSIONS.map(line),
		"  Account Resources: your account. Zone Resources: all zones on it (or just the domain you'll use).",
	].join("\n");
}

/** "1.5" < "1.6" < "1.10". */
export function isNewer(latest: string, current: string | null | undefined): boolean {
	if (!current) return true;
	const parse = (v: string) => (/^\d+(\.\d+)*$/.test(v) ? v.split(".").map(Number) : null);
	const a = parse(latest);
	const b = parse(current);
	if (!a) return false;
	if (!b) return true;
	for (let i = 0; i < Math.max(a.length, b.length); i++) {
		const d = (a[i] ?? 0) - (b[i] ?? 0);
		if (d !== 0) return d > 0;
	}
	return false;
}

export const HELP = `DMARC Reports installer

  npx @mrpwob/dmarc-reports setup    Install DMARC Reports on your own Cloudflare account
  npx @mrpwob/dmarc-reports update   Update it to the latest version

Options
  --account <id>     Cloudflare account to use, if your token reaches more than one
  --domain <name>    Domain for the app's address and your report address (setup)
  --trial            No domain: try the app on your workers.dev address (setup)
  --subdomain <x>    The app's address before the domain, "dmarc" by default (setup)
  --location <code>  Where your reports are kept: weur, eeur, enam, wnam, apac or oc (setup)
  -y, --yes          Answer yes to every question
  --force            Run an update even if you have the latest version

Your Cloudflare API token
  Set CLOUDFLARE_API_TOKEN, or paste it when asked. It's only ever sent to
  Cloudflare. The app's own files come inside this package.
`;

// -- The release ------------------------------------------------------------------------------------

export interface Asset {
	path: string;
	/** 32 hex characters: the start of a SHA-256 of the file's base64 plus its extension, as Wrangler does. */
	hash: string;
	size: number;
	contentType: string;
}

export interface Manifest {
	schema: 1;
	product: "dmarc-reports";
	version: string;
	builtAt: string;
	worker: { compatibilityDate: string; compatibilityFlags: string[]; crons: string[] };
	headers: string | null;
	assets: Asset[];
}

const CONTENT_TYPES: Record<string, string> = {
	js: "application/javascript", css: "text/css", html: "text/html", json: "application/json", txt: "text/plain",
	svg: "image/svg+xml", png: "image/png", jpg: "image/jpeg", webp: "image/webp", ico: "image/x-icon",
};

export function contentTypeFor(path: string): string {
	const file = path.slice(path.lastIndexOf("/") + 1);
	const dot = file.lastIndexOf(".");
	return CONTENT_TYPES[dot > 0 ? file.slice(dot + 1).toLowerCase() : ""] ?? "application/null";
}

export const isSafeVersion = (v: string) => /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/.test(v);

export function isManifest(value: unknown): value is Manifest {
	const m = value as Manifest;
	return Boolean(m && m.schema === 1 && m.product === "dmarc-reports" && typeof m.version === "string" && isSafeVersion(m.version) && m.worker && Array.isArray(m.assets));
}

// -- What the installer makes -----------------------------------------------------------------------

export interface Choice {
	accountId: string;
	/** null to try it on workers.dev (reports can't arrive until a domain's report address is routed to it). */
	domain: string | null;
	subdomain: string;
	location: Location;
}

const ACCOUNT_RE = /^[0-9a-f]{32}$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]$/;

export function parseChoice(v: { accountId?: unknown; domain?: unknown; subdomain?: unknown; location?: unknown }): Choice | null {
	if (typeof v.accountId !== "string" || !ACCOUNT_RE.test(v.accountId)) return null;
	const location = v.location === undefined ? "weur" : v.location;
	if (typeof location !== "string" || !Object.hasOwn(LOCATIONS, location)) return null;
	const subdomain = v.subdomain === undefined ? SUBDOMAIN : String(v.subdomain).trim().toLowerCase();
	if (!LABEL_RE.test(subdomain)) return null;
	if (v.domain === null || v.domain === undefined || v.domain === "") return { accountId: v.accountId, domain: null, subdomain, location: location as Location };
	const domain = String(v.domain).trim().toLowerCase().replace(/\.$/, "");
	if (!DOMAIN_RE.test(domain)) return null;
	return { accountId: v.accountId, domain, subdomain, location: location as Location };
}

export function hostname(choice: Choice, workersSubdomain?: string | null): string {
	if (choice.domain) return `${choice.subdomain}.${choice.domain}`;
	if (!workersSubdomain) throw new Error("No workers.dev subdomain on this account yet.");
	return `${SCRIPT}.${workersSubdomain}.workers.dev`;
}

export const reportAddressFor = (domain: string) => `${REPORT_USER}@${domain}`;

/** The link that lets you, and only you, set your password. It fills in the report address too. */
export function setupLink(host: string, token: string, report?: string | null): string {
	return `https://${host}/?setup=${encodeURIComponent(token)}${report ? `&report=${encodeURIComponent(report)}` : ""}`;
}

/** Metadata for PUT /accounts/:id/workers/scripts/dmarc-reports. Secrets already on the Worker are kept. */
export function metadata(manifest: Manifest, databaseId: string, assetsJwt: string): Record<string, unknown> {
	return {
		main_module: "worker.mjs",
		compatibility_date: manifest.worker.compatibilityDate,
		compatibility_flags: manifest.worker.compatibilityFlags,
		bindings: [
			{ type: "d1", name: "DB", id: databaseId },
			{ type: "assets", name: "ASSETS" },
			{ type: "send_email", name: "EMAIL" },
			{ type: "plain_text", name: "APP_VERSION", text: manifest.version },
		],
		keep_bindings: ["secret_text"],
		assets: { jwt: assetsJwt, config: { run_worker_first: ["/api/*"], ...(manifest.headers ? { _headers: manifest.headers } : {}) } },
		observability: { enabled: true },
	};
}
