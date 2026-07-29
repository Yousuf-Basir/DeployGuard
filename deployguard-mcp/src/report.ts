import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { checkResultShape, statusEnum } from "./schema.js";
import { checkDependencies } from "./deps.js";
import { checkFirewallStatus } from "./firewall.js";
import { checkFail2banStatus } from "./fail2ban.js";
import { checkAptSources } from "./apt.js";
import { checkApparmorAudit } from "./apparmor.js";

type Status = "ok" | "warn" | "fail";

interface CheckSummary {
  name: string;
  status: Status;
  summary: string;
}

export interface FullReportResult {
  status: Status;
  summary: string;
  checks: CheckSummary[];
  [key: string]: unknown;
}

// Maps each check to the binary system.check_dependencies would flag as
// missing for it, so a missing CLI tool skips the check instead of the
// check itself throwing or silently misreporting. apt.audit_sources needs
// no binary (it only reads files), so it always runs.
async function runOrSkip(
  checks: CheckSummary[],
  missingBins: Set<string>,
  name: string,
  requiredBin: string | null,
  fn: () => Promise<{ status: Status; summary: string }>
): Promise<void> {
  if (requiredBin && missingBins.has(requiredBin)) {
    checks.push({
      name,
      status: "fail",
      summary: `SKIPPED: ${requiredBin} is not installed, cannot run this check.`,
    });
    return;
  }
  const result = await fn();
  checks.push({ name, status: result.status, summary: result.summary });
}

export async function runFullReport(): Promise<FullReportResult> {
  const deps = await checkDependencies();
  const checks: CheckSummary[] = [
    { name: "system.check_dependencies", status: deps.status, summary: deps.summary },
  ];
  const missingBins = new Set(deps.missing.map((m) => m.bin));

  await runOrSkip(checks, missingBins, "firewall.check_status", "ufw", checkFirewallStatus);
  await runOrSkip(checks, missingBins, "fail2ban.get_status", "fail2ban-client", checkFail2banStatus);
  await runOrSkip(checks, missingBins, "apt.audit_sources", null, checkAptSources);
  await runOrSkip(checks, missingBins, "apparmor.audit", "aa-status", checkApparmorAudit);

  const overall: Status = checks.some((c) => c.status === "fail")
    ? "fail"
    : checks.some((c) => c.status === "warn")
    ? "warn"
    : "ok";

  const summary = [
    `Overall: ${overall.toUpperCase()}`,
    ...checks.map((c) => `\n[${c.name}] ${c.status.toUpperCase()}\n${c.summary}`),
  ].join("\n");

  return { status: overall, summary, checks };
}

export function registerReport(server: McpServer) {
  server.registerTool(
    "security.full_report",
    {
      description:
        "Runs a full security posture scan of this server: firewall, fail2ban brute-force protection, " +
        "AppArmor confinement, and APT source trust, then returns one consolidated pass/warn/fail report. " +
        "Call this when the user asks for a security check, security scan, security audit, or how secure " +
        "this server is — the single entry point for a general 'is this server secure' question, rather " +
        "than calling each individual check yourself.",
      outputSchema: {
        ...checkResultShape,
        checks: z.array(z.object({ name: z.string(), status: statusEnum, summary: z.string() })),
      },
    },
    async () => {
      const result = await runFullReport();
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
