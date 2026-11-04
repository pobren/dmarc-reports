// A D1 database in memory (node:sqlite), with the app's tables, for the tests.
import { DatabaseSync } from "node:sqlite";
import { SCHEMA } from "../src/schema.ts";
import { statements } from "../src/db.ts";

export function fakeD1(): { db: D1Database; sql: DatabaseSync } {
	const sql = new DatabaseSync(":memory:");
	for (const v of SCHEMA) for (const s of statements(v)) sql.exec(s);
	const prepare = (query: string) => {
		let args: unknown[] = [];
		const stmt = {
			bind: (...a: unknown[]) => ((args = a), stmt),
			run: async () => ({ success: true, meta: { changes: Number(sql.prepare(query).run(...(args as never[])).changes) } }),
			first: async () => sql.prepare(query).get(...(args as never[])) ?? null,
			all: async () => ({ results: sql.prepare(query).all(...(args as never[])) }),
		};
		return stmt;
	};
	const batch = async (list: { run: () => Promise<unknown> }[]) => {
		const out = [];
		for (const s of list) out.push(await s.run());
		return out;
	};
	return { db: { prepare, batch } as unknown as D1Database, sql };
}
