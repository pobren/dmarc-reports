// The AI connector at /mcp: add DMARC Reports to Claude, ChatGPT or any MCP app and ask "who sends email as my
// domain?" or "is anything failing DMARC?". It only reads. Sign in through OAuth (oauth.ts), or send an API key
// (keys.ts) from apps that let you add a header. The same answers as the public API (v1.ts).

import type { Resolve } from "./dns.ts";
import { periodOf } from "./reports.ts";
import { domainReports, domainSenders, domainSummary, domainTls, listDomains } from "./v1.ts";

const VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS = `DMARC Reports reads the DMARC and TLS reports mail providers send about one person's domains, and says in plain English who sends email as each domain and whether it passes.
- A sender is a service or server sending email as the domain. status is pass, warn, fail or info; label is mine or not when the owner has said.
- passRate is the whole percentage of emails that passed DMARC.
- days is 7, 30, 90 or 365.
- Times are UTC.
Start with list_domains.`;

const DAYS = { type: "integer", enum: [7, 30, 90, 365], description: "How many days back. Default 30." };
const DOMAIN = { type: "string", description: "One of the domains from list_domains, such as example.co.uk." };

const TOOLS = [
	{ name: "list_domains", title: "Your domains", description: "Every domain, its DMARC record and the last 30 days' emails and pass rate, plus the report address.", inputSchema: { type: "object", properties: {} } },
	{ name: "get_domain", title: "One domain", description: "Who sent email as a domain over a period, how much passed, the policy, and a plain-English headline.", inputSchema: { type: "object", properties: { domain: DOMAIN, days: DAYS }, required: ["domain"] } },
	{ name: "get_senders", title: "Senders", description: "Every sender for a domain with its verdict, why, and the steps to fix it if it's failing.", inputSchema: { type: "object", properties: { domain: DOMAIN, days: DAYS }, required: ["domain"] } },
	{ name: "get_reports", title: "Latest reports", description: "The latest DMARC reports that arrived for a domain: who sent them, the dates covered and the emails in each.", inputSchema: { type: "object", properties: { domain: DOMAIN, limit: { type: "integer", minimum: 1, maximum: 100 } }, required: ["domain"] } },
	{ name: "get_tls", title: "Encryption (TLS reports)", description: "How much email sent to the domain's mail servers was encrypted, and why any wasn't.", inputSchema: { type: "object", properties: { domain: DOMAIN, days: DAYS }, required: ["domain"] } },
].map((t) => ({ ...t, annotations: { title: t.title, readOnlyHint: true, openWorldHint: false } }));

type Rpc = { jsonrpc: "2.0"; id?: string | number | null; method?: string; params?: Record<string, unknown> };

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/** Handles one POST to the connector. The caller has already checked who it is. */
export async function handleMcp(request: Request, db: D1Database, resolve: Resolve, version: string): Promise<Response> {
	if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { allow: "POST" } });
	let body: unknown;
	try {
		body = await request.json();
	} catch {
		return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
	}
	const batch = Array.isArray(body);
	const messages = (batch ? body : [body]) as Rpc[];
	const replies = (await Promise.all(messages.map((m) => answer(m, db, resolve, version)))).filter((r) => r !== null);
	if (!replies.length) return new Response(null, { status: 202 });
	return json(batch ? replies : replies[0]);
}

async function answer(msg: Rpc, db: D1Database, _resolve: Resolve, version: string): Promise<unknown> {
	if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
		return { jsonrpc: "2.0", id: msg?.id ?? null, error: { code: -32600, message: "Invalid request" } };
	}
	if (msg.id === undefined || msg.id === null) return null; // a notification: nothing to send back
	const ok = (result: unknown) => ({ jsonrpc: "2.0", id: msg.id, result });
	switch (msg.method) {
		case "initialize": {
			const asked = String(msg.params?.protocolVersion ?? "");
			return ok({
				protocolVersion: VERSIONS.includes(asked) ? asked : VERSIONS[0],
				capabilities: { tools: {} },
				serverInfo: { name: "dmarc-reports", title: "DMARC Reports", version, websiteUrl: "https://paulobrien.dev/dmarc/" },
				instructions: INSTRUCTIONS,
			});
		}
		case "ping":
			return ok({});
		case "tools/list":
			return ok({ tools: TOOLS });
		case "tools/call": {
			const name = String(msg.params?.name ?? "");
			const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
			if (!TOOLS.some((t) => t.name === name)) return { jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: `Unknown tool: ${name}` } };
			try {
				const data = await callTool(name, args, db);
				return ok({ content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data });
			} catch (e) {
				return ok({ content: [{ type: "text", text: e instanceof Error ? e.message : "Something went wrong" }], isError: true });
			}
		}
		default:
			return { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } };
	}
}

async function callTool(name: string, args: Record<string, unknown>, db: D1Database): Promise<Record<string, unknown>> {
	if (name === "list_domains") return listDomains(db);
	const domain = String(args.domain ?? "").trim().toLowerCase().replace(/\.$/, "");
	if (!(await db.prepare("SELECT 1 FROM domains WHERE domain = ?").bind(domain).first())) throw new Error("That domain isn't in the list. Use list_domains to see them.");
	const days = periodOf(args.days);
	if (name === "get_domain") return (await domainSummary(db, domain, days))!;
	if (name === "get_senders") return domainSenders(db, domain, days);
	if (name === "get_reports") return domainReports(db, domain, Number(args.limit ?? 30));
	return domainTls(db, domain, days);
}
