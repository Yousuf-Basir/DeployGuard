import { mkdir, writeFile } from "node:fs/promises";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { run, runChecked } from "./exec.js";
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

// Which interpreter (if any) launches the app — "cpp"/"none" both mean the
// app's own binary is exec'd directly (a compiled binary, or a script whose
// interpreter is already covered some other way), so neither adds any
// interpreter-specific exec rule beyond what the own-directory rule already
// grants. Node and Python get their own common install-location rules below
// since — confirmed against a real deploy on the test VPS — a profile with
// no exec permission at all outside the project directory can't even launch
// an external interpreter, and this can't be assumed to be Node's paths only.
export type Runtime = "node" | "python" | "cpp" | "none";

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

// Confirmed against a real production Next.js deploy at "high" restriction:
// these are needed just to *boot* the process, at every level — not
// stack-specific hardening choices. Without them the app crash-loops (Node
// exits with EACCES reading OpenSSL's config, which happens even for
// plain-HTTP servers since the crypto stack still initializes) or silently
// fails to resolve hostnames. All read-only, so granting them doesn't weaken
// "high"'s deny-by-default posture for anything else.
function commonRuntimeFileRules(): string[] {
  return [
    "  /etc/ssl/openssl.cnf r,",
    "  /etc/nsswitch.conf r,",
    "  /etc/resolv.conf r,",
    "  /etc/host.conf r,",
    "  /etc/hosts r,",
    "  /run/resolvconf/resolv.conf r,",
    "  /proc/version_signature r,",
    "  /proc/*/cgroup r,",
    "  /proc/*/mountinfo r,",
    "  /sys/fs/cgroup/** r,",
  ];
}

// Runtime-specific filesystem needs beyond the universal baseline above.
// Confirmed against a real Flask deploy at "medium": a package installed
// via system pip (outside a venv) lands under /usr/local/lib/python3*/
// dist-packages, not /usr/lib (OS-owned packages only) — and pip's own
// console-script wrappers (e.g. /usr/local/bin/flask, the literal
// ExecStart target) need to be *read* by whoever launches them; a
// shebang script's interpreter line is read by the kernel and then again
// by the interpreter itself, separate from the interpreter's own exec
// permission (already granted by runtimeExecRules). "mr" not just "r" on
// the dist-packages tree — many packages ship compiled C extensions
// (.so) loaded via mmap(PROT_EXEC), which needs "m" specifically.
function runtimeFileRules(runtime: Runtime): string[] {
  if (runtime === "python") {
    return ["  /usr/local/lib/python3*/** mr,", "  /usr/local/bin/** r,"];
  }
  return [];
}

function filesystemRules(path: string, level: SecurityLevel, runtime: Runtime): string {
  // "ix" (not just "rw") so the app's own binary or shebang'd script inside
  // its own directory can execute regardless of stack — a compiled C++
  // binary, a venv's local interpreter copy, or a project-local script all
  // live here. This isn't "arbitrary system binary" exec (that's still
  // denied outside this directory at every level) — it's the app itself.
  const own = `  ${path}/** rwix,`;
  // The directory entry itself, not just globbed contents — Next.js (and
  // others) stat/list their own project root directory, which "**" alone
  // doesn't cover.
  const ownDir = `  ${path}/ r,`;
  const common = commonRuntimeFileRules();
  const runtimeExtra = runtimeFileRules(runtime);

  if (level === "high") return [own, ownDir, ...common, ...runtimeExtra].join("\n");
  if (level === "medium") {
    return [own, ownDir, "  /usr/lib/node_modules/** r,", "  /usr/lib/python3*/** r,", ...common, ...runtimeExtra].join(
      "\n"
    );
  }
  // low: broad read access already covers /usr/local/**, so runtimeExtra
  // would be redundant here — included anyway for one consistent code path.
  return [own, ownDir, "  /usr/** r,", "  /etc/** r,", ...common, ...runtimeExtra].join("\n");
}

// libuv's uv_interface_addresses — used by Node (and, via it, Next.js's dev
// banner printing "Network: http://<lan-ip>:<port>") to enumerate network
// interfaces — needs a netlink socket plus CAP_NET_ADMIN. Confirmed by the
// same real deploy: "high" denied this outright and the process never
// finished starting. Scoped to runtime "node" — Python/compiled binaries
// don't do this by default, so no need to grant it broadly.
function runtimeNetworkRules(runtime: Runtime): string[] {
  if (runtime === "node") {
    return ["  capability net_admin,", "  network netlink raw,"];
  }
  return [];
}

// Granted at every level, not a per-level tradeoff: DNS resolution over UDP
// is basic plumbing, not an optional feature, for any runtime that resolves
// hostnames (which is effectively all of them). Confirmed against a real
// Flask deploy at "medium" — glibc's resolver needs to *create* a UDP
// socket to actually query the nameserver in /etc/resolv.conf; read access
// on that file (commonRuntimeFileRules) alone doesn't help without this.
const DNS_NETWORK_RULES = ["  network inet dgram,", "  network inet6 dgram,"];

function networkRules(level: SecurityLevel, runtime: Runtime): string {
  const extra = runtimeNetworkRules(runtime);
  if (level === "high") {
    return [
      "  # only the port this service actually binds — replace with the real port",
      "  network inet stream,",
      // Confirmed against a real deploy (Node/Express's default app.listen(port)
      // with no explicit host binds a dual-stack IPv6 socket, which also serves
      // IPv4 clients) — without this, the socket still creates and LISTENs, but
      // AppArmor denies every accept() on it, and the runtime keeps retrying in
      // a tight loop: near-100% CPU, and every connection hangs until it times
      // out, rather than failing fast. That's worse than a deny-and-stop
      // failure, so this is granted at every level, not just medium/low.
      "  network inet6 stream,",
      ...DNS_NETWORK_RULES,
      ...extra,
    ].join("\n");
  }
  if (level === "medium") {
    return ["  network inet stream,", "  network inet6 stream,", ...DNS_NETWORK_RULES, ...extra].join("\n");
  }
  return ["  network,", ...extra].join("\n"); // low: unrestricted (DNS/extra both redundant here but harmless)
}

// Common install locations for each interpreter, both system-wide and the
// per-user version-manager directories (nvm, pyenv) real deploys actually
// use — not just the plain /usr/bin path a fresh apt install would give.
// The trailing "*" on binary names (node*, python3*) also catches version
// suffixes/symlinks (python3.11, node -> nodejs) without a rule per variant.
function runtimeExecRules(runtime: Runtime): string[] {
  if (runtime === "node") {
    return [
      "  # Node.js — common system and per-user version-manager (nvm) locations",
      "  /usr/bin/node* ix,",
      "  /usr/local/bin/node* ix,",
      "  /opt/*/bin/node* ix,",
      "  /root/.nvm/versions/node/*/bin/node* ix,",
      "  /home/*/.nvm/versions/node/*/bin/node* ix,",
    ];
  }
  if (runtime === "python") {
    return [
      "  # Python — common system and per-user version-manager (pyenv) locations",
      "  /usr/bin/python3* ix,",
      "  /usr/local/bin/python3* ix,",
      "  /opt/*/bin/python3* ix,",
      "  /root/.pyenv/versions/*/bin/python3* ix,",
      "  /home/*/.pyenv/versions/*/bin/python3* ix,",
    ];
  }
  // "cpp" and "none": the own-directory rwix rule (filesystemRules) already
  // covers exec'ing the app's own compiled binary — no external interpreter
  // to allow-list.
  return [];
}

function execRules(level: SecurityLevel, runtime: Runtime): string {
  const runtimeLines = runtimeExecRules(runtime);

  if (level === "high") {
    if (!runtimeLines.length) return "  # no exec of arbitrary system binaries at this level";
    return ["  # only the declared runtime may be exec'd — nothing else outside this app's own directory", ...runtimeLines].join(
      "\n"
    );
  }

  if (level === "medium") {
    return ["  # allow-listed commands for this stack only", "  /usr/bin/git ix,", ...runtimeLines].join("\n");
  }

  // low: broad exec allowed, plus /usr/local/bin (a common node/python
  // manual-install location the plain /usr and /bin patterns don't cover)
  return ["  /{usr/,}bin/** ix,", "  /usr/local/bin/** ix,", "  /opt/**/bin/** ix,", ...runtimeLines].join("\n");
}

export function buildProfile(path: string, type: ResourceType, level: SecurityLevel, runtime: Runtime = "none"): string {
  const name = sanitizeProfileName(path);
  return [
    "#include <tunables/global>",
    "",
    `# Generated by DeployGuard for ${path} (type: ${type}, level: ${level}, runtime: ${runtime}).`,
    `# This profile is not yet bound to a specific binary — attach it to the`,
    `# process that actually runs the app (a systemd unit's AppArmorProfile=,`,
    `# or ` + "`aa-exec -p " + name + " -- <command>`" + `) before loading.`,
    `profile ${name} flags=(attach_disconnected) {`,
    "  #include <abstractions/base>",
    "",
    filesystemRules(path, level, runtime),
    "",
    networkRules(level, runtime),
    "",
    execRules(level, runtime),
    "",
    alwaysDenyRules(),
    "}",
  ].join("\n");
}

export type ApparmorMode = "complain" | "enforce";

export interface ApplyProfileResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  mode: ApparmorMode;
  [key: string]: unknown;
}

// apparmor_parser (3.0.4, confirmed on the Ubuntu 22.04 test VPS) only has a
// flag to force *complain* mode (-C/--Complain) — there is no "--Enforce"
// counterpart. Enforce is simply the parser's default behavior when that
// flag is omitted (our generated profiles never set flags=(complain)
// themselves), so the enforce case passes no extra flag at all.
const PARSER_MODE_FLAGS: Record<ApparmorMode, string[]> = {
  complain: ["--Complain"],
  enforce: [],
};

// Stage 6: writes the profile (rebuilt from the same {path, type, level}
// inputs Stage 5 already validated, rather than trusting a profile blob
// passed back in) to its standard location, then loads it into the kernel.
// Binding it to an actual process is still not this tool's job — that's a
// systemd unit's AppArmorProfile= (Stage 8).
export async function applyProfile(
  path: string,
  type: ResourceType,
  level: SecurityLevel,
  mode: ApparmorMode,
  runtime: Runtime = "none"
): Promise<ApplyProfileResult> {
  if (!(await commandExists("apparmor_parser"))) {
    return {
      status: "fail",
      summary: "FAIL: apparmor_parser is not installed — install with: sudo apt install apparmor-utils",
      mode,
    };
  }

  const profile = buildProfile(path, type, level, runtime);
  const file = profileFilePath(path);

  try {
    await mkdir(PROFILE_DIR, { recursive: true });
    await writeFile(file, profile, "utf8");
  } catch (err: any) {
    return {
      status: "fail",
      summary: `FAIL: could not write profile to ${file}: ${err.message ?? err}`,
      mode,
    };
  }

  const { code, stderr } = await runChecked("apparmor_parser", ["-r", ...PARSER_MODE_FLAGS[mode], file]);

  if (code !== 0) {
    return {
      status: "fail",
      summary: `FAIL: apparmor_parser rejected the profile at ${file} (${mode} mode): ${stderr.trim() || "unknown error"}`,
      mode,
    };
  }

  return {
    status: "ok",
    summary: `OK: loaded ${file} in ${mode} mode. It confines nothing yet — bind it to a process via a ` +
      "systemd unit's AppArmorProfile= to actually enforce it.",
    mode,
  };
}

export function registerApparmor(server: McpServer) {
  server.registerTool(
    "apparmor.generate_profile",
    {
      description:
        "Builds an AppArmor confinement profile for a project/app directory at a chosen restriction level " +
        "(low/medium/high) — produces the profile text for review only, does not write, load, or apply it. " +
        "Call this when the user wants to sandbox, confine, or harden an app with AppArmor, or asks to " +
        "'secure my app'. Works for Node.js, Python, and compiled (C/C++) apps — pass 'runtime' matching the " +
        "stack so the profile allow-lists the right interpreter, if any. Use apparmor.apply_profile afterwards " +
        "to write and load the profile for real.",
      inputSchema: {
        path: z.string(),
        type: z.enum(["web-service"]),
        level: z.enum(["low", "medium", "high"]),
        runtime: z
          .enum(["node", "python", "cpp", "none"])
          .default("none")
          .describe(
            "The interpreter that launches this app, if any: 'node' or 'python' allow-list that interpreter's " +
              "common install locations (including nvm/pyenv); 'cpp' or 'none' assume a self-contained compiled " +
              "binary that needs no external interpreter allow-listed."
          ),
      },
      outputSchema: {
        profile: z.string(),
      },
    },
    async ({ path, type, level, runtime }) => {
      const profile = buildProfile(path, type, level, runtime);
      return {
        content: [{ type: "text" as const, text: profile }],
        structuredContent: { profile },
      };
    }
  );

  server.registerTool(
    "apparmor.apply_profile",
    {
      description:
        "Writes and loads an AppArmor profile for a project/app directory into the kernel — 'complain' mode " +
        "just logs violations, 'enforce' mode actually blocks them. Call this after the user has reviewed a " +
        "profile from apparmor.generate_profile and confirmed they want it applied for real. Always try " +
        "'complain' mode first to check for false-positive denials before switching to 'enforce'. Note: loading " +
        "the profile alone doesn't confine any running process yet — that needs a systemd unit to reference it.",
      inputSchema: {
        path: z.string(),
        type: z.enum(["web-service"]),
        level: z.enum(["low", "medium", "high"]),
        runtime: z.enum(["node", "python", "cpp", "none"]).default("none"),
        mode: z.enum(["complain", "enforce"]),
        confirm: z.literal(true),
      },
      outputSchema: {
        ...checkResultShape,
        mode: z.enum(["complain", "enforce"]),
      },
    },
    async ({ path, type, level, runtime, mode }) => {
      const result = await applyProfile(path, type, level, mode, runtime);
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
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
