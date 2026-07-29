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

// Stage 5: profile generation. Only "web-service" is implemented for now
// (the Next.js use case plan.md targets first) — other resource types get
// added as new template functions when there's a real need for them.
export type ResourceType = "web-service";
export type SecurityLevel = "low" | "medium" | "high";

function sanitizeProfileName(path: string): string {
  const cleaned = path.replace(/^\/+|\/+$/g, "").replace(/[^a-zA-Z0-9]+/g, ".");
  return `deployguard.${cleaned || "app"}`;
}

// AppArmor's standard profile directory — apparmor_parser and apparmor.d
// tooling expect profiles here, so apparmor.apply_profile (Stage 6) can
// load a known path instead of needing the profile text passed around.
const PROFILE_DIR = "/etc/apparmor.d";

export function profileFilePath(path: string): string {
  return `${PROFILE_DIR}/${sanitizeProfileName(path)}`;
}

// These four denials apply at every level, per plan.md §3.3.1 — no level
// is allowed to escalate past this floor.
function alwaysDenyRules(): string {
  return [
    "  deny /etc/passwd w,",
    "  deny /etc/shadow rw,",
    "  deny /etc/sudoers* rw,",
    "  deny /boot/** rw,",
    "  deny /lib/modules/** w,",
    "  deny capability sys_module,",
    "  deny capability sys_admin,",
    "  deny capability setuid,",
    "  deny capability setgid,",
  ].join("\n");
}

function filesystemRules(path: string, level: SecurityLevel): string {
  const own = `  ${path}/** rw,`;
  if (level === "high") return own; // own directory only, deny-by-default elsewhere
  if (level === "medium") {
    return [own, "  /usr/lib/node_modules/** r,", "  /etc/resolv.conf r,"].join("\n");
  }
  return [own, "  /usr/** r,", "  /etc/** r,"].join("\n"); // low: broad read access
}

function networkRules(level: SecurityLevel): string {
  if (level === "high") {
    return (
      "  # only the port this service actually binds — replace with the real port\n" +
      "  network inet stream,"
    );
  }
  if (level === "medium") {
    return "  network inet stream,\n  network inet6 stream,";
  }
  return "  network,"; // low: unrestricted
}

function execRules(level: SecurityLevel): string {
  if (level === "high") return "  # no exec of arbitrary system binaries at this level";
  if (level === "medium") {
    return ["  # allow-listed commands for this stack only", "  /usr/bin/node ix,", "  /usr/bin/npm ix,", "  /usr/bin/git ix,"].join(
      "\n"
    );
  }
  return "  /{usr/,}bin/** ix,"; // low: broad exec allowed
}

export function buildProfile(path: string, type: ResourceType, level: SecurityLevel): string {
  const name = sanitizeProfileName(path);
  return [
    "#include <tunables/global>",
    "",
    `# Generated by DeployGuard for ${path} (type: ${type}, level: ${level}).`,
    `# This profile is not yet bound to a specific binary — attach it to the`,
    `# process that actually runs the app (a systemd unit's AppArmorProfile=,`,
    `# or ` + "`aa-exec -p " + name + " -- <command>`" + `) before loading.`,
    `profile ${name} flags=(attach_disconnected) {`,
    "  #include <abstractions/base>",
    "",
    filesystemRules(path, level),
    "",
    networkRules(level),
    "",
    execRules(level),
    "",
    alwaysDenyRules(),
    "}",
  ].join("\n");
}

export function registerApparmor(server: McpServer) {
  server.registerTool(
    "apparmor.generate_profile",
    {
      description:
        "Builds an AppArmor confinement profile for a project/app directory at a chosen restriction level " +
        "(low/medium/high) — produces the profile text for review only, does not write, load, or apply it. " +
        "Call this when the user wants to sandbox, confine, or harden an app with AppArmor, or asks to " +
        "'secure my app'. Use apparmor.apply_profile afterwards to write and load the profile for real.",
      inputSchema: {
        path: z.string(),
        type: z.enum(["web-service"]),
        level: z.enum(["low", "medium", "high"]),
      },
      outputSchema: {
        profile: z.string(),
      },
    },
    async ({ path, type, level }) => {
      const profile = buildProfile(path, type, level);
      return {
        content: [{ type: "text" as const, text: profile }],
        structuredContent: { profile },
      };
    }
  );

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
