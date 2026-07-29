import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { run } from "./exec.js";
import { checkResultShape } from "./schema.js";

// ufw app profiles that resolve to well-known ports, so a named rule
// (e.g. "OpenSSH ALLOW IN Anywhere") doesn't silently bypass the port check.
const KNOWN_APP_PROFILES: Record<string, number[]> = {
  OpenSSH: [22],
  "Nginx Full": [80, 443],
  "Nginx HTTP": [80],
  "Nginx HTTPS": [443],
  "Apache Full": [80, 443],
  "Apache": [80],
  "Apache Secure": [443],
};

export interface FirewallResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  openPorts: number[];
  [key: string]: unknown;
}

export async function checkFirewallStatus(): Promise<FirewallResult> {
  const output = await run("ufw", ["status"]);

  if (/^Status:\s*inactive/im.test(output)) {
    return {
      status: "fail",
      summary:
        "FAIL: ufw is inactive — no firewall rules are being enforced. " +
        "Enable it with `sudo ufw enable` (first run `sudo ufw allow OpenSSH` " +
        "or `sudo ufw allow 22` so the SSH session isn't locked out).",
      openPorts: [],
    };
  }

  if (!/^Status:\s*active/im.test(output)) {
    return {
      status: "fail",
      summary:
        "FAIL: could not read ufw status. Is ufw installed? " +
        "Run system.check_dependencies to confirm.",
      openPorts: [],
    };
  }

  const openPorts = new Set<number>();
  const unrecognized: string[] = [];

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || /^(Status|Logging|Default|New profiles|To\s+Action\s+From|--\s+------\s+----)/i.test(trimmed)) {
      continue;
    }

    const portMatch = trimmed.match(/^(\d+)(?:\/(?:tcp|udp))?/);
    if (portMatch) {
      openPorts.add(Number(portMatch[1]));
      continue;
    }

    const nameMatch = trimmed.match(/^([A-Za-z][\w .]*?)\s{2,}/);
    const name = nameMatch?.[1]?.replace(/\s*\(v6\)$/, "").trim();
    if (name) {
      const ports = KNOWN_APP_PROFILES[name];
      if (ports) {
        ports.forEach((p) => openPorts.add(p));
      } else if (!unrecognized.includes(name)) {
        unrecognized.push(name);
      }
    }
  }

  const sortedPorts = [...openPorts].sort((a, b) => a - b);
  const unexpected = sortedPorts.filter((p) => p !== 80 && p !== 443);

  const lines: string[] = [];
  if (unexpected.length) {
    lines.push(`WARNING: unexpected ports open: ${unexpected.join(", ")}`);
  }
  if (unrecognized.length) {
    lines.push(`WARNING: unrecognized ufw rule(s), review manually: ${unrecognized.join(", ")}`);
  }
  if (!lines.length) {
    lines.push("OK: only 80/443 open");
  }

  return {
    status: unexpected.length || unrecognized.length ? "warn" : "ok",
    summary: lines.join("\n"),
    openPorts: sortedPorts,
  };
}

export function registerFirewall(server: McpServer) {
  server.registerTool(
    "firewall.check_status",
    {
      description:
        "Checks which ports are open on this server's firewall and flags anything besides 80/443. " +
        "Call this when the user asks what ports are open, whether the firewall is configured/enabled, " +
        "or wants a firewall/network exposure check. Reads ufw status (v1 supports ufw only).",
      outputSchema: {
        ...checkResultShape,
        openPorts: z.array(z.number()),
      },
    },
    async () => {
      const result = await checkFirewallStatus();
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
