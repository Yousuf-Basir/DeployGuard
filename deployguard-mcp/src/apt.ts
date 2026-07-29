import { readFile, readdir } from "node:fs/promises";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { checkResultShape } from "./schema.js";

// Hostnames considered trusted sources for APT repositories.
// Keep short and hardcoded for v1 (per plan.md) — a config-file-driven
// allowlist is a later addition, not needed until this outgrows a few lines.
const TRUSTED_HOSTS = [
  /(^|\.)archive\.ubuntu\.com$/,
  /^security\.ubuntu\.com$/,
  /^old-releases\.ubuntu\.com$/,
  /^ports\.ubuntu\.com$/,
  /^deb\.debian\.org$/,
  /^security\.debian\.org$/,
  /^ftp\.debian\.org$/,
  /^deb\.nodesource\.com$/,
  /^download\.docker\.com$/,
  /^packages\.microsoft\.com$/,
  /^apt\.postgresql\.org$/,
  /^ppa\.launchpad(content)?\.net$/,
];

export interface AptSource {
  url: string;
  hostname: string;
}

export interface AptResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  untrustedSources: AptSource[];
  [key: string]: unknown;
}

function parseSourceLines(content: string): AptSource[] {
  const sources: AptSource[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^(deb|deb-src)\s+(?:\[[^\]]*\]\s+)?(\S+)/);
    if (!match) continue;
    const url = match[2];
    try {
      sources.push({ url, hostname: new URL(url).hostname });
    } catch {
      // not a parseable URL, skip
    }
  }
  return sources;
}

async function readAllSourceFiles(): Promise<AptSource[]> {
  const sources: AptSource[] = [];

  try {
    sources.push(...parseSourceLines(await readFile("/etc/apt/sources.list", "utf8")));
  } catch {
    // no main sources.list — unusual but not fatal, keep scanning sources.list.d
  }

  try {
    const dir = "/etc/apt/sources.list.d";
    const files = await readdir(dir);
    for (const file of files) {
      if (!file.endsWith(".list")) continue; // deb822 .sources format not handled in v1
      sources.push(...parseSourceLines(await readFile(`${dir}/${file}`, "utf8")));
    }
  } catch {
    // sources.list.d doesn't exist — fine, nothing to add
  }

  return sources;
}

function isTrusted(hostname: string): boolean {
  return TRUSTED_HOSTS.some((pattern) => pattern.test(hostname));
}

export async function checkAptSources(): Promise<AptResult> {
  const sources = await readAllSourceFiles();
  const seen = new Set<string>();
  const untrustedSources: AptSource[] = [];

  for (const source of sources) {
    const key = `${source.hostname}${source.url}`;
    if (seen.has(key) || isTrusted(source.hostname)) continue;
    seen.add(key);
    untrustedSources.push(source);
  }

  const summary = untrustedSources.length
    ? `WARNING: untrusted APT source(s): ${untrustedSources.map((s) => s.hostname).join(", ")}`
    : "OK: all APT sources are on the trusted allowlist";

  return {
    status: untrustedSources.length ? "warn" : "ok",
    summary,
    untrustedSources,
  };
}

export function registerApt(server: McpServer) {
  server.registerTool(
    "apt.audit_sources",
    {
      description:
        "Checks whether this server's APT package sources (/etc/apt/sources.list and sources.list.d) come " +
        "from trusted repositories (official Ubuntu/Debian mirrors, well-known vendor repos). Call this when " +
        "the user asks about package sources, APT repositories, where packages come from, or supply-chain trust.",
      outputSchema: {
        ...checkResultShape,
        untrustedSources: z.array(z.object({ url: z.string(), hostname: z.string() })),
      },
    },
    async () => {
      const result = await checkAptSources();
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
