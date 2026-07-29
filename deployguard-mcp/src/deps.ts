import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { run } from "./exec.js";
import { checkResultShape } from "./schema.js";

const REQUIRED = [
  { bin: "ufw", installHint: "sudo apt install ufw" },
  { bin: "fail2ban-client", installHint: "sudo apt install fail2ban" },
  { bin: "aa-status", installHint: "sudo apt install apparmor" },
  { bin: "apt-get", installHint: null }, // ships with Debian/Ubuntu, not expected to be missing
];

export async function checkDebianBased(): Promise<boolean> {
  try {
    const osRelease = await readFile("/etc/os-release", "utf8");
    return /^(ID|ID_LIKE)=.*\bdebian\b/im.test(osRelease);
  } catch {
    return false;
  }
}

export async function commandExists(bin: string): Promise<boolean> {
  const output = await run("which", [bin]);
  return output.trim().length > 0;
}

export function registerCheckDependencies(server: McpServer) {
  server.registerTool(
    "system.check_dependencies",
    {
      description:
        "Checks whether this server/host is ready for DeployGuard security tooling. Call this when the user " +
        "asks if the server is ready, what's installed, or wants a security setup checked. Confirms OS " +
        "compatibility and that ufw/fail2ban/AppArmor tooling are installed.",
      outputSchema: {
        ...checkResultShape,
        debianBased: z.boolean(),
        missing: z.array(z.object({ bin: z.string(), installHint: z.string() })),
      },
    },
    async () => {
      const isDebianBased = await checkDebianBased();
      const missing: { bin: string; installHint: string }[] = [];
      for (const { bin, installHint } of REQUIRED) {
        if (!(await commandExists(bin)) && installHint) missing.push({ bin, installHint });
      }
      const lines = [
        isDebianBased ? "OK: Debian-based OS" : "WARNING: not a Debian-based OS — v1 only supports Debian/Ubuntu",
        ...missing.map((m) => `MISSING: ${m.bin} — install with: ${m.installHint}`),
      ];
      const summary = lines.join("\n");
      const status = !isDebianBased ? "fail" : missing.length ? "warn" : "ok";
      return {
        content: [{ type: "text" as const, text: summary }],
        structuredContent: { status, summary, debianBased: isDebianBased, missing },
      };
    }
  );
}
