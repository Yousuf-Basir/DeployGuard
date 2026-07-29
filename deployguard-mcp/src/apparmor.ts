import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { run } from "./exec.js";
import { commandExists } from "./deps.js";
import { checkResultShape } from "./schema.js";

export interface Profile {
  name: string;
  mode: "enforce" | "complain" | "kill" | "unconfined";
}

export interface ApparmorAuditResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  profiles: Profile[];
  [key: string]: unknown;
}

const MODES = ["enforce", "complain", "kill", "unconfined"] as const;

function parseAaStatus(output: string): {
  moduleLoaded: boolean;
  profiles: Profile[];
  unconfinedProcesses: number;
  mixedProcesses: number;
} {
  const moduleLoaded = /apparmor module is loaded/i.test(output);
  const profiles: Profile[] = [];
  let currentMode: Profile["mode"] | null = null;
  let unconfinedProcesses = 0;
  let mixedProcesses = 0;

  for (const raw of output.split("\n")) {
    const line = raw.trim();
    if (!line) continue;

    const profileModeMatch = line.match(/^\d+ profiles are in (\w+) mode\.$/);
    if (profileModeMatch) {
      const mode = profileModeMatch[1].toLowerCase();
      currentMode = (MODES as readonly string[]).includes(mode) ? (mode as Profile["mode"]) : null;
      continue;
    }

    if (/^\d+ processes/.test(line)) {
      currentMode = null;
      const unconfinedMatch = line.match(/^(\d+) processes are unconfined but have a profile defined\.$/);
      if (unconfinedMatch) unconfinedProcesses = Number(unconfinedMatch[1]);
      const mixedMatch = line.match(/^(\d+) processes are in mixed mode\.$/);
      if (mixedMatch) mixedProcesses = Number(mixedMatch[1]);
      continue;
    }

    if (/^\d+ profiles are loaded\.$/.test(line)) {
      currentMode = null;
      continue;
    }

    if (currentMode && !/^\d/.test(line)) {
      profiles.push({ name: line, mode: currentMode });
    }
  }

  return { moduleLoaded, profiles, unconfinedProcesses, mixedProcesses };
}

export async function checkApparmorAudit(): Promise<ApparmorAuditResult> {
  if (!(await commandExists("aa-status"))) {
    return {
      status: "fail",
      summary: "FAIL: AppArmor is not installed — install with: sudo apt install apparmor",
      profiles: [],
    };
  }

  const output = await run("aa-status", []);
  const { moduleLoaded, profiles, unconfinedProcesses, mixedProcesses } = parseAaStatus(output);

  if (!moduleLoaded) {
    return {
      status: "fail",
      summary: "FAIL: the AppArmor kernel module is not loaded.",
      profiles: [],
    };
  }

  const risky = profiles.filter((p) => p.mode !== "enforce");
  const warnings: string[] = [];
  if (risky.length) {
    warnings.push(
      `${risky.length} profile(s) not in enforce mode: ${risky.map((p) => `${p.name} (${p.mode})`).join(", ")}`
    );
  }
  if (unconfinedProcesses > 0) {
    warnings.push(`${unconfinedProcesses} process(es) have a profile defined but are running unconfined`);
  }
  if (mixedProcesses > 0) {
    warnings.push(`${mixedProcesses} process(es) are in mixed mode`);
  }

  const summary = warnings.length
    ? `WARNING: ${warnings.join("; ")}`
    : `OK: ${profiles.length} profile(s) loaded, all in enforce mode`;

  return {
    status: warnings.length ? "warn" : "ok",
    summary,
    profiles,
  };
}

export function registerApparmor(server: McpServer) {
  server.registerTool(
    "apparmor.audit",
    {
      description:
        "Checks AppArmor's status on this server: which profiles are loaded, what mode each is in " +
        "(enforce/complain/unconfined), and whether any confined process is actually running unprotected. " +
        "Call this when the user asks about AppArmor, app confinement/sandboxing, or which apps have no " +
        "security profile enforced.",
      outputSchema: {
        ...checkResultShape,
        profiles: z.array(z.object({ name: z.string(), mode: z.string() })),
      },
    },
    async () => {
      const result = await checkApparmorAudit();
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
