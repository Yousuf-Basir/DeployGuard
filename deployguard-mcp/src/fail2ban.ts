import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { run } from "./exec.js";
import { commandExists } from "./deps.js";
import { checkResultShape } from "./schema.js";

export interface Jail {
  name: string;
  currentlyBanned: number;
  totalBanned: number;
}

export interface Fail2banResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  jails: Jail[];
  [key: string]: unknown;
}

async function getJailNames(): Promise<string[] | null> {
  const output = await run("fail2ban-client", ["status"]);
  const match = output.match(/Jail list:\s*([^\n]*)/);
  if (!match) return null;
  return match[1]
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

async function getJailDetail(name: string): Promise<Jail> {
  const output = await run("fail2ban-client", ["status", name]);
  const currentlyBanned = Number(output.match(/Currently banned:\s*(\d+)/)?.[1] ?? 0);
  const totalBanned = Number(output.match(/Total banned:\s*(\d+)/)?.[1] ?? 0);
  return { name, currentlyBanned, totalBanned };
}

export async function checkFail2banStatus(): Promise<Fail2banResult> {
  if (!(await commandExists("fail2ban-client"))) {
    return {
      status: "fail",
      summary: "FAIL: fail2ban is not installed — install with: sudo apt install fail2ban",
      jails: [],
    };
  }

  const jailNames = await getJailNames();
  if (jailNames === null) {
    return {
      status: "fail",
      summary:
        "FAIL: fail2ban is installed but not running — start it with: sudo systemctl start fail2ban",
      jails: [],
    };
  }

  if (jailNames.length === 0) {
    return {
      status: "warn",
      summary: "WARNING: fail2ban is running but no jails are configured — nothing is being protected.",
      jails: [],
    };
  }

  const jails = await Promise.all(jailNames.map(getJailDetail));
  const summary = `OK: ${jails.length} jail(s) active — ${jails
    .map((j) => `${j.name} (${j.currentlyBanned} banned)`)
    .join(", ")}`;

  return { status: "ok", summary, jails };
}

export function registerFail2ban(server: McpServer) {
  server.registerTool(
    "fail2ban.get_status",
    {
      description:
        "Checks fail2ban's brute-force protection status: whether it's installed and running, which jails " +
        "(sshd, nginx, etc.) are active, and current/total ban counts. Call this when the user asks about " +
        "brute-force protection, banned IPs, fail2ban jails, or repeated failed login attempts.",
      outputSchema: {
        ...checkResultShape,
        jails: z.array(
          z.object({
            name: z.string(),
            currentlyBanned: z.number(),
            totalBanned: z.number(),
          })
        ),
      },
    },
    async () => {
      const result = await checkFail2banStatus();
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
