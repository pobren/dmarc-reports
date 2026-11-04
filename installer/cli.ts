// `npx @mrpwob/dmarc-reports`: installs and updates DMARC Reports on the person's own Cloudflare account from
// their terminal, with a Cloudflare API token they make themselves. The token only ever goes to
// api.cloudflare.com. The app's files come inside this package (release/), so nothing else is downloaded.
//
// Built into one file by `npm run package` (see installer/package.ts).

import { createInterface } from "node:readline/promises";
import process from "node:process";
import { readFile } from "node:fs/promises";
import { HELP, LOCATIONS, SCRIPT, SUBDOMAIN, UsageError, isManifest, isNewer, parseArgs, parseChoice, reportAddressFor, setupLink, tokenHelp, type Choice, type Manifest, type Options } from "./core.ts";
import { InstallError, address, call, database, describe, installed, route, setupCode, worker, type Context } from "./run.ts";

declare const CLI_VERSION: string;

const { stdin, stdout } = process;
const RELEASE_DIR = new URL("./release/", import.meta.url);

// -- Talking to the person --------------------------------------------

const tty = stdout.isTTY;
const paint = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = paint("1");
const dim = paint("2");
const red = paint("31");
const green = paint("32");
const yellow = paint("33");
const say = (s = "") => stdout.write(`${s}\n`);

class Stop extends Error {}

let rl: ReturnType<typeof createInterface> | null = null;
const prompts = () => (rl ??= createInterface({ input: stdin, output: stdout, terminal: tty }));

async function ask(question: string, fallback = ""): Promise<string> {
	if (!stdin.isTTY) {
		if (fallback) return fallback;
		throw new Stop(`${question.trim()} needs an answer, but there's no keyboard to type one. Use the options (npx @mrpwob/dmarc-reports help).`);
	}
	const answer = (await prompts().question(`${question}${fallback ? dim(` (${fallback})`) : ""} `)).trim();
	return answer || fallback;
}

async function confirm(question: string, opts: Options, fallback = false): Promise<boolean> {
	if (opts.yes) return true;
	if (!stdin.isTTY) return fallback;
	const answer = (await ask(`${question} ${dim(fallback ? "[Y/n]" : "[y/N]")}`)).toLowerCase();
	return answer ? answer.startsWith("y") : fallback;
}

/** Asks for the token without showing it on screen. */
async function askSecret(question: string): Promise<string> {
	if (!stdin.isTTY) throw new Stop("No Cloudflare API token. Set CLOUDFLARE_API_TOKEN and run the command again.");
	const r = prompts();
	const out = r as unknown as { _writeToOutput?: (s: string) => void };
	const original = out._writeToOutput;
	stdout.write(question + " ");
	out._writeToOutput = (s: string) => {
		if (s.includes("\n") || s.includes("\r")) stdout.write("\n");
	};
	try {
		return (await r.question("")).trim();
	} finally {
		out._writeToOutput = original;
	}
}

async function choose<T>(question: string, items: T[], label: (t: T) => string, extra?: string): Promise<number> {
	items.forEach((t, i) => say(`  ${bold(String(i + 1))}  ${label(t)}`));
	if (extra) say(`  ${bold("0")}  ${extra}`);
	for (;;) {
		const n = Number(await ask(question, items.length === 1 && !extra ? "1" : ""));
		if (Number.isInteger(n) && n >= (extra ? 0 : 1) && n <= items.length) return n - 1;
		say(yellow(`Please type a number from ${extra ? 0 : 1} to ${items.length}.`));
	}
}

// -- Cloudflare -------------------------------------------------------

async function getToken(): Promise<string> {
	let token = (process.env.CLOUDFLARE_API_TOKEN ?? "").trim();
	if (!token) {
		say(`The installer needs a Cloudflare API token to set things up on your account.\n${tokenHelp()}\n`);
		token = await askSecret("Paste your API token:");
	}
	if (!token) throw new Stop("No token, so nothing was changed.");
	const verify = await call<{ status?: string }>(token, "GET", "/user/tokens/verify");
	if (!verify.ok || verify.result?.status !== "active") {
		throw new Stop(`Cloudflare didn't accept that API token. It needs to be an active user API token (not a Global API Key). ${describe(verify)}`);
	}
	return token;
}

async function pickAccount(token: string, opts: Options, filter?: (id: string) => Promise<boolean>): Promise<{ id: string; name: string }> {
	const r = await call<{ id: string; name: string }[]>(token, "GET", "/accounts?per_page=50");
	if (!r.ok) throw new Stop(`We couldn't list your Cloudflare accounts. Your token needs "Account Settings: Read". ${describe(r)}`);
	let accounts = r.result ?? [];
	if (opts.account) {
		accounts = accounts.filter((a) => a.id === opts.account);
		if (!accounts.length) throw new Stop(`Your token can't reach account ${opts.account}.`);
	}
	if (filter) {
		const keep = await Promise.all(accounts.map((a) => filter(a.id)));
		accounts = accounts.filter((_, i) => keep[i]);
	}
	if (!accounts.length) throw new Stop(filter ? "DMARC Reports isn't installed on any account this token can reach. To install it, run npx @mrpwob/dmarc-reports setup." : "Your token doesn't reach any Cloudflare account. Check its Account Resources.");
	if (accounts.length === 1) return accounts[0];
	say(bold("Which Cloudflare account?"));
	return accounts[await choose("Account:", accounts, (a) => `${a.name} ${dim(a.id)}`)];
}

async function loadManifest(): Promise<Manifest> {
	const m = JSON.parse(await readFile(new URL("manifest.json", RELEASE_DIR), "utf8").catch(() => "null"));
	if (!isManifest(m)) throw new Stop("This package is missing its app files. Please run the command again with @latest.");
	return m;
}

const reader = async (path: string) => {
	if (path.split("/").includes("..")) throw new Error("Bad path");
	return new Uint8Array(await readFile(new URL(path.replace(/^\/+/, ""), RELEASE_DIR)));
};

async function step<T>(label: string, run: () => Promise<T>): Promise<T> {
	stdout.write(`${dim("…")} ${label}${tty ? "" : "\n"}`);
	try {
		const out = await run();
		if (tty) stdout.write("\r\x1b[2K");
		say(`${green("✓")} ${label}`);
		return out;
	} catch (e) {
		if (tty) stdout.write("\n");
		if (!(e instanceof InstallError)) throw e;
		say(red(`✗ ${e.message}`));
		if (e.link) say(`  ${e.link.text}: ${e.link.href}`);
		if (e.detail) say(dim(`  Cloudflare said: ${e.detail}`));
		if (/HTTP 40[13]\b/.test(e.detail ?? "")) say(`\n${tokenHelp()}`);
		say(dim("\nAnything already done is kept, so running the command again carries on from here."));
		throw new Stop("");
	}
}

// -- Commands ---------------------------------------------------------

async function setup(opts: Options) {
	say(bold("Install DMARC Reports on your Cloudflare account\n"));
	const token = await getToken();
	const account = await pickAccount(token, opts);

	if (await installed(token, account.id)) {
		say(yellow(`DMARC Reports is already installed on ${account.name}.`));
		if (!(await confirm("Run setup again? Your reports are kept, and you get a new link to reset your password. (For a plain update, use npx @mrpwob/dmarc-reports update.)", opts))) return;
	}

	let domain = opts.domain;
	if (domain === undefined) {
		const zones = await call<{ name: string; status: string }[]>(token, "GET", `/zones?account.id=${account.id}&per_page=50`);
		if (!zones.ok) throw new Stop(`We couldn't list your domains. Your token needs "Zone: Read". ${describe(zones)}`);
		const active = (zones.result ?? []).filter((z) => z.status === "active");
		say(bold("\nWhich domain should the app and your report address use?"));
		say(dim("  Pick one whose email is handled by Cloudflare Email Routing, or a spare domain. Reports for all your other domains can come here too."));
		const i = await choose("Domain:", active, (z) => z.name, "No domain yet: try it on my workers.dev address");
		domain = i < 0 ? "" : active[i].name;
	}

	let subdomain = opts.subdomain;
	if (domain && subdomain === undefined) subdomain = await ask(`\nWeb address: what goes before ${domain}?`, SUBDOMAIN);

	let location = opts.location;
	if (location === undefined) {
		const places = Object.entries(LOCATIONS);
		say(bold("\nWhere should your reports be kept? Pick the place nearest to you."));
		location = places[await choose("Place:", places, ([, name]) => name)][0];
	}

	const choice = parseChoice({ accountId: account.id, domain, subdomain, location });
	if (!choice) throw new Stop("That domain, web address or place doesn't look right. Please check it and run the command again.");
	const manifest = await loadManifest();
	const ctx: Context = { token, choice, manifest, read: reader };
	const report = choice.domain ? reportAddressFor(choice.domain) : null;

	say(`\nInstalling DMARC Reports ${manifest.version} on ${bold(account.name)}${choice.domain ? ` for ${bold(choice.domain)}` : ""}.\n`);
	const databaseId = await step("Making the database", () => database(ctx));
	await step("Uploading the app", () => worker(ctx, databaseId));
	const host = await step("Giving it its web address", () => address(ctx));
	const routed = report ? await step(`Sending ${report} to the app`, () => route(ctx, report)) : null;
	const code = await step("Locking the set-up to you", () => setupCode(ctx));

	say();
	say(bold("DMARC Reports is installed."));
	say(`  It's at ${bold(`https://${host}`)}`);
	if (routed && !routed.routed) {
		say();
		if (routed.why === "off") {
			say(yellow(`  One thing left: Email Routing isn't switched on for ${choice.domain}.`));
			say("  Switching it on changes where the domain's email goes, so we've left that to you.");
			say(`  If ${choice.domain} has no other email, switch it on, then add a custom address`);
			say(`  ${bold(report!)} with the action "Send to a Worker" and the Worker ${bold(SCRIPT)}.`);
			say(`  If its email goes to Google, Microsoft or someone else, use a spare domain instead.`);
		} else {
			say(yellow(`  One thing left: ${report} already goes somewhere else in Email Routing.`));
			say(`  Change its action to "Send to a Worker" and the Worker ${bold(SCRIPT)}.`);
		}
		say(`  ${routed.link}`);
	}
	say();
	say("  Set your password here:");
	say(`  ${bold(setupLink(host, code, report))}`);
	say(dim("  Only this link can set the password, so keep it to yourself. Running setup again makes a new one."));
	if (!host.endsWith(".workers.dev")) say(dim("  A brand-new address can take a few minutes to start working."));
	say();
	say(dim("Run npx @mrpwob/dmarc-reports@latest update any time to get the newest version."));
}

/** The domain and address of an existing install, from the custom domains on its Worker. */
async function existingChoice(token: string, accountId: string): Promise<Choice> {
	const r = await call<{ hostname: string; zone_name: string; service: string }[]>(token, "GET", `/accounts/${accountId}/workers/domains?service=${SCRIPT}`);
	if (!r.ok) throw new Stop(`We couldn't read the app's address. Your token needs "Workers: Admin". ${describe(r)}`);
	const mine = (r.result ?? []).find((d) => d.service === SCRIPT);
	if (!mine) return { accountId, domain: null, subdomain: SUBDOMAIN, location: "weur" };
	const zone = mine.zone_name.toLowerCase();
	const host = mine.hostname.toLowerCase();
	const subdomain = host.endsWith(`.${zone}`) ? host.slice(0, -zone.length - 1) : SUBDOMAIN;
	return { accountId, domain: zone, subdomain, location: "weur" };
}

async function update(opts: Options) {
	say(bold("Update DMARC Reports\n"));
	const token = await getToken();
	const account = await pickAccount(token, opts, (id) => installed(token, id));
	const choice = await existingChoice(token, account.id);
	const manifest = await loadManifest();

	const settings = await call<{ bindings?: { name: string; type: string; text?: string }[] }>(token, "GET", `/accounts/${account.id}/workers/scripts/${SCRIPT}/settings`);
	const current = settings.result?.bindings?.find((b) => b.name === "APP_VERSION")?.text ?? null;
	if (!isNewer(manifest.version, current) && !opts.force) {
		say(`${green("✓")} DMARC Reports ${manifest.version} is the latest version, and ${account.name} already has it.`);
		say(dim("  To run the update anyway, add --force."));
		return;
	}
	say(`Updating ${bold(account.name)} from ${current ?? "an older version"} to ${bold(manifest.version)}.\n`);
	const ctx: Context = { token, choice, manifest, read: reader };
	const databaseId = await step("Finding your database", () => database(ctx));
	await step("Uploading the new version", () => worker(ctx, databaseId));
	say();
	say(bold("DMARC Reports is up to date. Your reports and settings are just as they were."));
}

async function main() {
	let opts: Options;
	try {
		opts = parseArgs(process.argv.slice(2));
	} catch (e) {
		if (e instanceof UsageError) {
			say(red(e.message));
			process.exitCode = 2;
			return;
		}
		throw e;
	}
	try {
		if (opts.command === "version") say(CLI_VERSION);
		else if (opts.command === "help") say(`${HELP}\n${tokenHelp()}`);
		else if (opts.command === "setup") await setup(opts);
		else await update(opts);
	} catch (e) {
		if (e instanceof Stop) {
			if (e.message) say(red(`\n${e.message}`));
		} else {
			say(red(`\nSomething unexpected went wrong. Nothing is lost: please run the command again.\n${String((e as Error)?.stack ?? e)}`));
		}
		process.exitCode = 1;
	} finally {
		rl?.close();
	}
}

main();
