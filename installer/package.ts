// Builds the npm package `@mrpwob/dmarc-reports` into npm/: the command-line installer (npm/cli.mjs) and the
// app it installs (npm/release/: worker.mjs, the web pages and manifest.json). Run from the repo root:
//
//   npm run package
//   cd npm && npm publish        (the release workflow does this)
//
// The version comes from the root package.json.

import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { CRON, contentTypeFor, isSafeVersion, type Manifest } from "./core.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmDir = join(root, "npm");
const out = join(npmDir, "release");
const publicDir = join(root, "public");
const toPosix = (p: string) => p.split(sep).join("/");

function walk(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : e.isFile() ? [join(dir, e.name)] : []));
}

/** As Wrangler does: a hash of the base64 contents plus the extension, cut to 32 hex characters. */
function assetHash(file: string): string {
	const ext = extname(file).slice(1);
	return createHash("sha256").update(readFileSync(file).toString("base64") + ext).digest("hex").slice(0, 32);
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string };
if (!isSafeVersion(pkg.version)) throw new Error(`Version "${pkg.version}" isn't safe.`);
const wrangler = JSON.parse(readFileSync(join(root, "wrangler.jsonc"), "utf8").replace(/^\s*\/\/.*$/gm, "")) as { compatibility_date: string; compatibility_flags?: string[]; triggers: { crons: string[] } };
if (wrangler.triggers.crons[0] !== CRON) throw new Error("The cron in wrangler.jsonc and installer/core.ts differ.");

rmSync(npmDir, { recursive: true, force: true });
mkdirSync(join(out, "assets"), { recursive: true });

// 1. The Worker, in one file.
await build({
	entryPoints: [join(root, "src/index.ts")],
	outfile: join(out, "worker.mjs"),
	bundle: true,
	platform: "neutral",
	format: "esm",
	target: "es2022",
	mainFields: ["module", "main"],
	conditions: ["workerd", "worker", "browser"],
	external: ["cloudflare:*", "node:*"],
	define: { "process.env.NODE_ENV": '"production"' },
	banner: { js: `// DMARC Reports ${pkg.version}. Business Source License 1.1. https://github.com/pobren/dmarc-reports` },
});

// 2. The web pages. _headers becomes a setting, as Wrangler does.
const files = walk(publicDir).filter((f) => toPosix(relative(publicDir, f)) !== "_headers");
for (const f of files) {
	const target = join(out, "assets", relative(publicDir, f));
	mkdirSync(dirname(target), { recursive: true });
	cpSync(f, target);
}
const assets = files
	.map((f) => {
		const path = `/${toPosix(relative(publicDir, f))}`;
		return { path, hash: assetHash(f), size: statSync(f).size, contentType: contentTypeFor(path) };
	})
	.sort((a, b) => a.path.localeCompare(b.path));

const manifest: Manifest = {
	schema: 1,
	product: "dmarc-reports",
	version: pkg.version,
	builtAt: new Date().toISOString(),
	worker: { compatibilityDate: wrangler.compatibility_date, compatibilityFlags: wrangler.compatibility_flags ?? [], crons: [CRON] },
	headers: readFileSync(join(publicDir, "_headers"), "utf8"),
	assets,
};
writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, "\t"));

// 3. The installer, in one file.
await build({
	entryPoints: [join(root, "installer/cli.ts")],
	outfile: join(npmDir, "cli.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node20",
	banner: { js: `#!/usr/bin/env node\n// DMARC Reports installer ${pkg.version}. Business Source License 1.1. https://github.com/pobren/dmarc-reports` },
	define: { CLI_VERSION: JSON.stringify(pkg.version) },
});

// 4. The package's own files.
const npmPkg = JSON.parse(readFileSync(join(root, "installer/package.json"), "utf8"));
writeFileSync(join(npmDir, "package.json"), `${JSON.stringify({ ...npmPkg, version: pkg.version }, null, "\t")}\n`);
for (const f of ["README.md", "LICENSE", "NOTICE"]) cpSync(join(root, f === "README.md" ? "installer/README.md" : f), join(npmDir, f));

console.log(`@mrpwob/dmarc-reports ${pkg.version}: worker ${(statSync(join(out, "worker.mjs")).size / 1024).toFixed(0)} KB, ${assets.length} web files, in npm/`);
