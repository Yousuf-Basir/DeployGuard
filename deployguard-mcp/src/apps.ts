import { readFile, readdir, writeFile, unlink } from "node:fs/promises";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { runChecked } from "./exec.js";
import { checkResultShape } from "./schema.js";
import { UNIT_DIR, unitName, unitFilePath, buildUnit, parseUnitFile } from "./systemd.js";

const UNIT_FILE_RE = /^deployguard-.*\.service$/;

async function listUnitFileNames(): Promise<string[]> {
  try {
    const files = await readdir(UNIT_DIR);
    return files.filter((f) => UNIT_FILE_RE.test(f));
  } catch {
    return [];
  }
}

async function unitFileExists(name: string): Promise<boolean> {
  return (await listUnitFileNames()).includes(`${unitName(name)}.service`);
}

async function isActive(unit: string): Promise<boolean> {
  const { stdout } = await runChecked("systemctl", ["is-active", unit]);
  return stdout.trim() === "active";
}

async function isEnabled(unit: string): Promise<boolean> {
  const { stdout } = await runChecked("systemctl", ["is-enabled", unit]);
  return stdout.trim() === "enabled";
}

export interface AppSummary {
  name: string;
  unit: string;
  active: boolean;
  enabled: boolean;
  user: string;
  path: string;
  profile: string;
}

export interface AppsListResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  apps: AppSummary[];
  [key: string]: unknown;
}

// Scans installed unit files rather than just currently-running units, so a
// stopped app still shows up — "list everything DeployGuard has deployed,"
// not "list what's currently up." Reuses systemd.ts's own parseUnitFile
// instead of re-deriving User=/WorkingDirectory=/AppArmorProfile= here.
export async function listApps(): Promise<AppsListResult> {
  const unitFiles = await listUnitFileNames();
  const apps: AppSummary[] = await Promise.all(
    unitFiles.map(async (fileName) => {
      const content = await readFile(`${UNIT_DIR}/${fileName}`, "utf8");
      const parsed = parseUnitFile(fileName, content);
      const unit = unitName(parsed.name);
      const [active, enabled] = await Promise.all([isActive(unit), isEnabled(unit)]);
      return {
        name: parsed.name,
        unit,
        active,
        enabled,
        user: parsed.user,
        path: parsed.path,
        profile: parsed.appArmorProfile,
      };
    })
  );

  const status = apps.some((a) => !a.active) ? "warn" : "ok"; // zero apps is "ok" — nothing deployed yet, not a failure
  const summary = apps.length
    ? apps.map((a) => `${a.name}: ${a.active ? "active" : "inactive"}${a.enabled ? "" : " (disabled)"}`).join(", ")
    : "No apps deployed by DeployGuard yet.";

  return { status, summary, apps };
}

export interface AppActionResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  [key: string]: unknown;
}

async function requireExists(name: string): Promise<AppActionResult | null> {
  if (await unitFileExists(name)) return null;
  return {
    status: "fail",
    summary: `FAIL: no app named "${name}" is deployed by DeployGuard (no ${unitName(name)}.service installed).`,
  };
}

export async function stopApp(name: string): Promise<AppActionResult> {
  const missing = await requireExists(name);
  if (missing) return missing;

  const unit = unitName(name);
  const { code, stderr } = await runChecked("systemctl", ["stop", unit]);
  if (code !== 0) {
    return { status: "fail", summary: `FAIL: systemctl stop ${unit} failed: ${stderr.trim() || "unknown error"}` };
  }
  return { status: "ok", summary: `OK: ${unit}.service stopped.` };
}

export async function restartApp(name: string): Promise<AppActionResult> {
  const missing = await requireExists(name);
  if (missing) return missing;

  const unit = unitName(name);
  const { code, stderr } = await runChecked("systemctl", ["restart", unit]);
  if (code !== 0) {
    return { status: "fail", summary: `FAIL: systemctl restart ${unit} failed: ${stderr.trim() || "unknown error"}` };
  }
  return { status: "ok", summary: `OK: ${unit}.service restarted.` };
}

// Deliberately narrow: removes only the systemd unit. The project
// directory, service account, and AppArmor profile are separate, harder-to
// -reverse actions this tool does not perform — see plan.md §6 on whether a
// fuller teardown tool is ever wanted.
export async function removeApp(name: string): Promise<AppActionResult> {
  const missing = await requireExists(name);
  if (missing) return missing;

  const unit = unitName(name);
  await runChecked("systemctl", ["stop", unit]);
  await runChecked("systemctl", ["disable", unit]);
  try {
    await unlink(unitFilePath(name));
  } catch (err: any) {
    return { status: "fail", summary: `FAIL: could not delete ${unitFilePath(name)}: ${err.message ?? err}` };
  }
  await runChecked("systemctl", ["daemon-reload"]);
  return {
    status: "ok",
    summary: `OK: ${unit}.service removed. Project directory, service account, and AppArmor profile were left untouched.`,
  };
}

export interface UpdateLimitsResult extends AppActionResult {
  cpuQuota?: string;
  memoryMax?: string;
}

// No new state store — the installed unit file is the only source of
// truth. Reads it back via parseUnitFile, rebuilds via the same buildUnit
// template systemd.apply_unit uses with the new limit values substituted
// in, keeping every other field (user/path/startCommand/appArmorProfile)
// exactly as already deployed.
export async function updateLimits(name: string, cpuQuota?: string, memoryMax?: string): Promise<UpdateLimitsResult> {
  const missing = await requireExists(name);
  if (missing) return missing;

  const file = unitFilePath(name);
  const content = await readFile(file, "utf8");
  const parsed = parseUnitFile(`${unitName(name)}.service`, content);

  const unit = buildUnit({
    name: parsed.name,
    path: parsed.path,
    user: parsed.user,
    startCommand: parsed.startCommand,
    appArmorProfile: parsed.appArmorProfile,
    cpuQuota: cpuQuota ?? parsed.cpuQuota,
    memoryMax: memoryMax ?? parsed.memoryMax,
  });

  try {
    await writeFile(file, unit, "utf8");
  } catch (err: any) {
    return { status: "fail", summary: `FAIL: could not write ${file}: ${err.message ?? err}` };
  }

  const reload = await runChecked("systemctl", ["daemon-reload"]);
  if (reload.code !== 0) {
    return { status: "fail", summary: `FAIL: systemctl daemon-reload failed: ${reload.stderr.trim() || "unknown error"}` };
  }

  const unitId = unitName(name);
  const restart = await runChecked("systemctl", ["restart", unitId]);
  if (restart.code !== 0) {
    return {
      status: "fail",
      summary: `FAIL: limits updated but systemctl restart ${unitId} failed: ${restart.stderr.trim() || "unknown error"}`,
    };
  }

  return {
    status: "ok",
    summary: `OK: ${unitId}.service updated (cpuQuota=${cpuQuota ?? parsed.cpuQuota ?? "none"}, memoryMax=${
      memoryMax ?? parsed.memoryMax ?? "none"
    }) and restarted.`,
    cpuQuota: cpuQuota ?? parsed.cpuQuota,
    memoryMax: memoryMax ?? parsed.memoryMax,
  };
}

export async function getLogs(name: string, lines: number, since?: string): Promise<{ logs: string }> {
  const args = ["-u", unitName(name), "-n", String(lines), "--no-pager"];
  if (since) args.push("--since", since);
  const { stdout, stderr } = await runChecked("journalctl", args);
  return { logs: stdout || stderr };
}

export function registerApps(server: McpServer) {
  server.registerTool(
    "apps.list",
    {
      description:
        "Lists every application deployed by DeployGuard and its current status (active/inactive, enabled, " +
        "service user, project path, AppArmor profile) — including apps that are currently stopped, not just " +
        "running ones. Call this when the user asks to list, show, or see all apps/services DeployGuard " +
        "manages, or 'what's running', instead of reconstructing this via raw systemctl/ps commands.",
      outputSchema: {
        ...checkResultShape,
        apps: z.array(
          z.object({
            name: z.string(),
            unit: z.string(),
            active: z.boolean(),
            enabled: z.boolean(),
            user: z.string(),
            path: z.string(),
            profile: z.string(),
          })
        ),
      },
    },
    async () => {
      const result = await listApps();
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );

  server.registerTool(
    "apps.stop",
    {
      description:
        "Stops an app deployed by DeployGuard. Call this when the user asks to stop, pause, or shut down a " +
        "specific deployed app by name.",
      inputSchema: { name: z.string(), confirm: z.literal(true) },
      outputSchema: checkResultShape,
    },
    async ({ name }) => {
      const result = await stopApp(name);
      return { content: [{ type: "text" as const, text: result.summary }], structuredContent: result };
    }
  );

  server.registerTool(
    "apps.restart",
    {
      description:
        "Restarts an app deployed by DeployGuard. Call this when the user asks to restart or reload a " +
        "specific deployed app by name.",
      inputSchema: { name: z.string(), confirm: z.literal(true) },
      outputSchema: checkResultShape,
    },
    async ({ name }) => {
      const result = await restartApp(name);
      return { content: [{ type: "text" as const, text: result.summary }], structuredContent: result };
    }
  );

  server.registerTool(
    "apps.remove",
    {
      description:
        "Removes a DeployGuard-deployed app's systemd unit — stops it, disables it, and deletes the unit " +
        "file. Call this when the user asks to delete, remove, or tear down a deployed app by name. " +
        "Deliberately narrow: leaves the project directory, service account, and AppArmor profile untouched " +
        "(those are separate, harder-to-reverse actions this tool does not perform).",
      inputSchema: { name: z.string(), confirm: z.literal(true) },
      outputSchema: checkResultShape,
    },
    async ({ name }) => {
      const result = await removeApp(name);
      return { content: [{ type: "text" as const, text: result.summary }], structuredContent: result };
    }
  );

  server.registerTool(
    "apps.update_limits",
    {
      description:
        "Changes an already-deployed app's CPU/RAM limits (systemd CPUQuota=/MemoryMax=) and restarts it. " +
        "Call this when the user asks to change, set, or adjust an app's CPU or memory limit. Rewrites the " +
        "existing unit file with the new values, keeping everything else (service user, path, start command, " +
        "AppArmor profile) exactly as already deployed — no separate limits store to keep in sync.",
      inputSchema: {
        name: z.string(),
        cpuQuota: z.string().optional(),
        memoryMax: z.string().optional(),
        confirm: z.literal(true),
      },
      outputSchema: {
        ...checkResultShape,
        cpuQuota: z.string().optional(),
        memoryMax: z.string().optional(),
      },
    },
    async ({ name, cpuQuota, memoryMax }) => {
      const result = await updateLimits(name, cpuQuota, memoryMax);
      return { content: [{ type: "text" as const, text: result.summary }], structuredContent: result };
    }
  );

  server.registerTool(
    "apps.get_logs",
    {
      description:
        "Gets recent logs for an app deployed by DeployGuard (wraps journalctl). Call this when the user " +
        "asks to see logs, output, or recent activity for a specific deployed app. Read-only — no confirmation " +
        "needed.",
      inputSchema: {
        name: z.string(),
        lines: z.number().optional(),
        since: z.string().optional(),
      },
      outputSchema: {
        logs: z.string(),
      },
    },
    async ({ name, lines, since }) => {
      const result = await getLogs(name, lines ?? 100, since);
      return {
        content: [{ type: "text" as const, text: result.logs }],
        structuredContent: result,
      };
    }
  );
}
