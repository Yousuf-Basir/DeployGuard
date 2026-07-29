import { writeFile } from "node:fs/promises";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { runChecked } from "./exec.js";
import { checkResultShape } from "./schema.js";
import { checkApparmorAudit } from "./apparmor.js";

export interface UnitInput {
  name: string;
  path: string;
  user: string;
  startCommand: string;
  appArmorProfile: string;
  cpuQuota?: string;
  memoryMax?: string;
}

// Every unit DeployGuard creates lives here and carries this prefix —
// callers only ever supply the short app name, tools derive the rest, so
// Stage 10's apps.list can reliably enumerate by the "deployguard-*" glob.
const UNIT_DIR = "/etc/systemd/system";

export function unitName(name: string): string {
  return `deployguard-${name}`;
}

export function unitFilePath(name: string): string {
  return `${UNIT_DIR}/${unitName(name)}.service`;
}

// Stage 8: the template that actually ties DAC (Stage 7's service account),
// MAC (Stage 6's loaded AppArmor profile), and optional cgroup resource
// limits together — this is what runs the app, replacing PM2 or any other
// process manager for anything DeployGuard deploys.
export function buildUnit(input: UnitInput): string {
  const lines = [
    "[Unit]",
    `Description=DeployGuard-managed app: ${input.name}`,
    "After=network.target",
    "",
    "[Service]",
    "Type=simple",
    `User=${input.user}`,
    `Group=${input.user}`,
    `WorkingDirectory=${input.path}`,
    `ExecStart=${input.startCommand}`,
    `AppArmorProfile=${input.appArmorProfile}`,
    "Restart=on-failure",
  ];
  if (input.cpuQuota) lines.push(`CPUQuota=${input.cpuQuota}`);
  if (input.memoryMax) lines.push(`MemoryMax=${input.memoryMax}`);
  lines.push("", "[Install]", "WantedBy=multi-user.target");
  return lines.join("\n");
}

export interface ParsedUnit {
  name: string;
  user: string;
  path: string;
  startCommand: string;
  appArmorProfile: string;
  cpuQuota?: string;
  memoryMax?: string;
}

// Reused as-is by Stage 10's apps.list/apps.update_limits, not duplicated
// there — the installed unit file is the only source of truth, no separate
// metadata store to keep in sync.
export function parseUnitFile(unitFileName: string, content: string): ParsedUnit {
  const field = (key: string): string | undefined => {
    const match = content.match(new RegExp(`^${key}=(.*)$`, "m"));
    return match?.[1]?.trim();
  };
  const shortName = unitFileName.replace(/^deployguard-/, "").replace(/\.service$/, "");
  return {
    name: shortName,
    user: field("User") ?? "",
    path: field("WorkingDirectory") ?? "",
    startCommand: field("ExecStart") ?? "",
    appArmorProfile: field("AppArmorProfile") ?? "",
    cpuQuota: field("CPUQuota"),
    memoryMax: field("MemoryMax"),
  };
}

export interface ApplyUnitResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  unit: string;
  [key: string]: unknown;
}

// The binary the service account actually needs to execute — startCommand's
// first token, quotes stripped. Best-effort: doesn't handle a startCommand
// that's itself a shell pipeline ("bash -c '...'"), only the common
// "/path/to/binary arg1 arg2" case every stage so far has used.
function execTarget(startCommand: string): string {
  return startCommand.trim().split(/\s+/)[0]?.replace(/^["']|["']$/g, "") ?? "";
}

// Confirms the service account can actually reach and execute the binary
// before the unit is ever written or started — without this, a binary
// installed under a directory the account can't traverse (the single most
// common real case: Node installed via nvm under a user's home directory,
// e.g. /root/.nvm or /home/*/.nvm, which is 0700/0750 and invisible to any
// other account) silently crash-loops (systemd exit code 203/EXEC) and the
// only way to find out why is digging through journalctl/dmesg after the
// fact. Failing here instead turns that into one clear, actionable error.
async function checkExecutable(user: string, bin: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!bin) return { ok: false, reason: "startCommand is empty — nothing to execute." };

  const existsAsRoot = (await runChecked("test", ["-e", bin])).code === 0;
  if (!existsAsRoot) {
    return { ok: false, reason: `"${bin}" (from startCommand) does not exist on this host.` };
  }

  const canExec = (await runChecked("runuser", ["-u", user, "--", "test", "-x", bin])).code === 0;
  if (!canExec) {
    const binName = bin.split("/").pop();
    return {
      ok: false,
      reason:
        `service account "${user}" cannot execute "${bin}" — most likely a parent directory isn't ` +
        "traversable by that account. This is common with Node/Python installed via a per-user version " +
        "manager (nvm, pyenv) under a home directory that's 0700/0750 by default (e.g. /root/.nvm, " +
        "/home/*/.nvm) — those tools are designed for one interactive login shell, not a locked-down system " +
        `account. Fix by COPYING the binary out to a system-wide location — \`cp "$(command -v ${binName})" ` +
        `/usr/local/bin/${binName} && chmod 755 /usr/local/bin/${binName}\` — not a symlink: a symlink still ` +
        "resolves through the original restricted directory when the service account tries to open it, so it " +
        "fails the exact same way. Installing the runtime via your distro's package manager/NodeSource instead " +
        "of a per-user version manager avoids this entirely. Then retry with the new path.",
    };
  }

  return { ok: true };
}

// Writes the unit, confirms the AppArmor profile it references is actually
// loaded (checked against apparmor.audit's own view of the kernel state
// rather than re-running apparmor.apply_profile's write-and-load path,
// since this tool only has a profile *name*, not the {path,type,level}
// apply_profile needs to rebuild one from scratch), then starts it.
export async function applyUnit(input: UnitInput): Promise<ApplyUnitResult> {
  const unit = unitName(input.name);
  const audit = await checkApparmorAudit();
  const profile = audit.profiles.find((p) => p.name === input.appArmorProfile);

  if (!profile) {
    return {
      status: "fail",
      summary:
        `FAIL: AppArmor profile "${input.appArmorProfile}" is not loaded — run apparmor.apply_profile ` +
        "for it first, then retry.",
      unit,
    };
  }

  const execCheck = await checkExecutable(input.user, execTarget(input.startCommand));
  if (!execCheck.ok) {
    return {
      status: "fail",
      summary: `FAIL: ${execCheck.reason}`,
      unit,
    };
  }

  const file = unitFilePath(input.name);
  try {
    await writeFile(file, buildUnit(input), "utf8");
  } catch (err: any) {
    return {
      status: "fail",
      summary: `FAIL: could not write unit file ${file}: ${err.message ?? err}`,
      unit,
    };
  }

  const reload = await runChecked("systemctl", ["daemon-reload"]);
  if (reload.code !== 0) {
    return {
      status: "fail",
      summary: `FAIL: systemctl daemon-reload failed: ${reload.stderr.trim() || "unknown error"}`,
      unit,
    };
  }

  const enable = await runChecked("systemctl", ["enable", "--now", unit]);
  if (enable.code !== 0) {
    return {
      status: "fail",
      summary: `FAIL: systemctl enable --now ${unit} failed: ${enable.stderr.trim() || "unknown error"}`,
      unit,
    };
  }

  const modeNote =
    profile.mode === "complain"
      ? ` Note: the profile is still in complain mode — it logs violations but doesn't block them yet.`
      : "";

  return {
    status: "ok",
    summary:
      `OK: ${unit}.service written, loaded, and started as ${input.user} under AppArmor profile ` +
      `${input.appArmorProfile}.${modeNote}`,
    unit,
  };
}

export function registerSystemd(server: McpServer) {
  const unitInputSchema = {
    name: z.string(),
    path: z.string(),
    user: z.string(),
    startCommand: z.string(),
    appArmorProfile: z.string(),
    cpuQuota: z.string().optional(),
    memoryMax: z.string().optional(),
  };

  server.registerTool(
    "systemd.generate_unit",
    {
      description:
        "Builds a systemd unit file (text only, not written or started) that would run an app as its own " +
        "service account under its AppArmor profile, with optional CPU/RAM limits. Call this when the user " +
        "wants to review a deployment's systemd unit before it's applied. Use systemd.apply_unit afterwards " +
        "to actually write and start it.",
      inputSchema: unitInputSchema,
      outputSchema: {
        unit: z.string(),
      },
    },
    async (input) => {
      const unit = buildUnit(input);
      return {
        content: [{ type: "text" as const, text: unit }],
        structuredContent: { unit },
      };
    }
  );

  server.registerTool(
    "systemd.apply_unit",
    {
      description:
        "Writes a systemd unit to /etc/systemd/system/, confirms its AppArmor profile is loaded, then " +
        "enables and starts it — the step that actually runs the app under DeployGuard's DAC+MAC+systemd " +
        "deployment, replacing PM2 or any other process manager. Call this after the user has reviewed the " +
        "unit from systemd.generate_unit and confirmed they want it deployed for real. Requires the app's " +
        "service account (serviceuser.create) and AppArmor profile (apparmor.apply_profile) to already exist. " +
        "Fails fast with a specific fix (rather than starting a crash-looping service) if the service account " +
        "can't actually execute startCommand's binary — the most common cause is a runtime installed via nvm " +
        "or a similar per-user version manager under a home directory the service account can't traverse.",
      inputSchema: {
        ...unitInputSchema,
        confirm: z.literal(true),
      },
      outputSchema: {
        ...checkResultShape,
        unit: z.string(),
      },
    },
    async (input) => {
      const result = await applyUnit(input);
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
