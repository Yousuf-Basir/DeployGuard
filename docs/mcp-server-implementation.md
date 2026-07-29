# DeployGuard MCP Server — Implementation Guide

Keep this simple: one server, one file per check, no framework layers. The goal is something a single person can read top to bottom in five minutes and get running in five more.

**v1 scope:** Debian-based OS only (Debian/Ubuntu). Firewall support is `ufw` only — no `iptables`/`firewalld` adapters yet, those come later as separate files without touching anything else. Trying to run on a non-Debian host or a server without `ufw` should fail clearly, not silently do the wrong thing (see §3, `system.check_dependencies`).

## 1. Two Use Cases This Serves

**A. Ad-hoc security scan.** Agent calls the read-only checks (firewall, fail2ban, AppArmor, APT sources) anytime and reports back pass/warn/fail. No project context needed — this is "how's this server doing right now."

**B. Guided secure deployment.** The flow you actually want, e.g. for a Next.js app — and note this is **deploying an app DeployGuard will own**, not just hardening one that's already running under something else (PM2, a bare `node` process). That distinction matters because it's also responsible for **redeploying updates** to that same app later, and once the project directory belongs to its own dedicated Unix account (step 4 below), pulling new code has to happen as that account, not as root or whichever user is running the agent.

*First deploy:*

1. User points the agent at a project's repo ("deploy this app at `/var/www/myapp` with high restriction").
2. Agent reads the project itself (`package.json`, framework, port it binds, entry point) — that's normal file reading, not an MCP tool. DeployGuard's tools never parse `package.json` or guess a start command themselves; the agent always supplies it as explicit input.
3. Agent asks the user to pick a restriction level if not already given: **Low / Medium / High** (per plan.md §3.5.1).
4. Agent calls `apparmor.generate_profile` with `{ path, type: "web-service", level }` — server builds the profile from a template, returns the text, not yet applied. Agent shows it, asks for confirmation, then `apparmor.apply_profile` (`confirm: true`) loads it in `complain` mode first, then `enforce` once the agent/user is satisfied nothing's being falsely denied.
5. Agent calls `serviceuser.create` (`confirm: true`) — creates a dedicated unprivileged Unix account for the app and re-owns the project directory to it.
6. Agent calls `systemd.generate_unit` with the service account, the AppArmor profile name, the start command it read from the project, and any resource limits the user wants — reviews the unit with the user, then `systemd.apply_unit` (`confirm: true`) writes it, loads the profile, and starts the service.

*Redeploying an update:*

1. User asks to deploy the latest change ("redeploy myapp" / "deploy the latest update").
2. Agent calls `deploy.update` (`confirm: true`) — server looks up who actually owns the project directory (not a guessed naming convention), pulls and rebuilds **as that account** via `runuser`, then restarts the systemd unit.

*Managing a deployed app day-to-day (the PM2-equivalent surface):*

1. User asks "list all applications deployed by deployguard" / "what apps are running" — agent calls `apps.list`, which enumerates every `deployguard-*.service` unit regardless of current state.
2. User asks to stop, restart, or delete a specific app by name — agent calls `apps.stop` / `apps.restart` / `apps.remove` (`confirm: true`) against that unit. `apps.remove` only removes the systemd unit — the project directory, service account, and AppArmor profile are left alone, a deliberately narrower action than a full teardown.
3. User asks to change an app's CPU/RAM limit — agent calls `apps.update_limits` (`confirm: true`), which rewrites the existing unit with the new limits without needing any new place to store them (the installed unit file is the only state).
4. User asks for an app's logs — agent calls `apps.get_logs`, a read-only wrapper around `journalctl -u deployguard-<name>.service`.

This is why `apparmor.generate_profile` and the deployment/lifecycle tools are in v1 even though they write something — this guided flow is the actual product, not a "stretch" feature. Nothing gets applied, written, executed, stopped, or deleted without an explicit confirm at each enforce-tier step; `apps.list` and `apps.get_logs` stay confirm-free since they're read-only.

## 2. Tech Stack

- **TypeScript + Node.js**, using the official [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk).
- **stdio transport only.** That's all a local agent needs to launch the server as a subprocess. No HTTP/SSE, no webhook mode, until something actually requires it.
- Each tool shells out to an existing CLI (`ufw`, `fail2ban-client`, `aa-status`, `apt`, `apparmor_parser`), parses/generates plain text, and applies a simple rule. Nothing more.
- Every tool declares an `outputSchema` and returns `structuredContent` alongside its `content` text (see §4, "Output convention"). MCP only standardizes the server↔client data contract, not how a client's model narrates it back to the user — `structuredContent` is the one lever we have to make results machine-parseable and consistent across agents, since different clients will always phrase the prose differently.

## 3. File Structure

```
deployguard-mcp/
├── package.json
├── tsconfig.json
├── README.md              # the getting-started guide, §5 below
│
└── src/
    ├── index.ts           # creates the server, registers every tool, starts stdio transport
    ├── exec.ts            # one helper: run a fixed CLI command safely, return stdout
    ├── schema.ts           # shared { status, summary } output shape every tool's outputSchema extends
    ├── deps.ts            # system.check_dependencies — is this Debian-based, is ufw/fail2ban/apparmor-utils installed
    │
    ├── firewall.ts        # firewall.check_status (ufw only in v1)
    ├── fail2ban.ts        # fail2ban.get_status
    ├── apt.ts              # apt.audit_sources
    ├── report.ts           # security.full_report — calls the checks above and merges results
    │
    ├── apparmor.ts        # apparmor.audit, apparmor.generate_profile, apparmor.apply_profile
    ├── serviceuser.ts     # serviceuser.create — dedicated Unix account per app (DAC)
    ├── systemd.ts          # systemd.generate_unit, systemd.apply_unit — ties DAC + MAC + resource limits together
    │                       # also exports the unit-file-parsing helper apps.ts reuses (User=/WorkingDirectory=/etc.)
    ├── deploy.ts           # deploy.update — pull + build + restart as the app's own service user
    └── apps.ts             # apps.list, apps.stop, apps.restart, apps.remove, apps.update_limits, apps.get_logs
```

Still no `adapters/`, no `policy/` layer, no per-type template files — `apparmor.ts` holds three small template strings (one per level: low/medium/high) as plain functions, not a plugin system. If it outgrows one file later, split it then. `firewall.ts` today only knows how to call `ufw`; an `iptables.ts`/`firewalld.ts` alongside it later is an additive change, not a rewrite. Same for `systemd.ts` — one file, one unit template function, no per-framework variants until there's a real second one needed.

## 4. Tool Pattern

### Discoverability — descriptions and server instructions

Confirmed by testing: an agent given a generic prompt ("check if system is ready") with no mention of "DeployGuard" or the tool name will spend time exploring project files trying to disambiguate intent before it even weighs a tool call — and if it's launched from inside this repo, that exploration is slow (reads through docs, package.json, source). Same prompt with "use DeployGuard mcp" is instant, because the ambiguity is gone. The fix isn't telling users to say the magic words — it's writing tool metadata that resolves the ambiguity itself. Two levers, both apply to **every tool this server registers, present and future**, not just `system.check_dependencies`:

**1. Tool `description` — trigger language, not implementation notes.** A description is matched against however a user actually phrases the request, so write it that way:

```ts
// weak — describes internals, doesn't match how someone would ask
description: "Checks OS compatibility and whether ufw/fail2ban/apparmor-utils are installed."

// better — includes the phrasing a user would actually use
description:
  "Checks whether this server/host is ready for DeployGuard security tooling. " +
  "Call this when the user asks if the server is ready, what's installed, or wants " +
  "a security setup checked. Confirms OS compatibility and that ufw/fail2ban/apparmor-utils are installed."
```

**2. Server-level `instructions` — standing guidance independent of any one tool.** `McpServer`'s constructor takes an options object with an `instructions` string (surfaced to the client at connect time, per the MCP spec's `initialize` response). Set it once in `index.ts` and keep it updated as tools are added — it's living text, not a Stage 0 one-off:

```ts
// src/index.ts
const server = new McpServer(
  { name: "deployguard", version: "0.1.0" },
  {
    instructions:
      "DeployGuard checks and hardens security on this host (firewall, fail2ban, AppArmor, APT sources). " +
      "For any question about this server's security status, readiness, or hardening, prefer calling these " +
      "tools over reading source files or reasoning from general knowledge. Call system.check_dependencies " +
      "first if unsure whether the required CLI tools are installed.",
  }
);
```

Not every client honors `instructions` (it's optional per spec), so it's a supplement to good descriptions, not a replacement for them.

### Output convention — every tool returns `structuredContent`

Different agents render the same tool result differently — one might build a table, another a bullet list, another just prose (confirmed empirically: same `system.check_dependencies` call, different clients, different shapes). MCP has no mechanism to control that final narration — it's generated by the client's own model. What MCP does give us is `outputSchema` + `structuredContent`: a typed JSON result alongside the text, which a compliant client can read programmatically instead of re-deriving structure from prose every time. It doesn't force every agent's chat reply to look identical, but it's the one part of the contract actually under our control, and it means any future non-LLM consumer (a script, a dashboard) doesn't need to parse English sentences either.

Every tool shares one minimal base shape, defined once in `schema.ts`:

```ts
// src/schema.ts
import { z } from "zod";

export const statusEnum = z.enum(["ok", "warn", "fail"]);

// Base fields every tool's outputSchema extends with its own specifics.
export const checkResultShape = {
  status: statusEnum,
  summary: z.string(), // one-line human-readable summary, same text used in `content`
};
```

`status` is always one of `ok` / `warn` / `fail` — no tool invents its own vocabulary for pass/fail. Each tool's `outputSchema` spreads `checkResultShape` and adds whatever fields are specific to that check (e.g. `missing` for dependency check, `openPorts` for firewall). The handler returns both `content` (plain text, what today's tools already produce) and `structuredContent` (the same information, typed) — `content` keeps working for clients that only read text, `structuredContent` is there for clients that use it.

### Dependency check — run this first

Before any real check, the agent should call `system.check_dependencies`. It confirms the host is Debian-based and reports which of `ufw`, `fail2ban`, `apparmor-utils`, and `apt` are actually installed, so the agent can tell the user exactly what's missing instead of a check silently failing or an enforce command erroring out mid-way:

```ts
// src/deps.ts
import { z } from "zod";
import { checkResultShape } from "./schema.js";

const REQUIRED = [
  { bin: "ufw", installHint: "sudo apt install ufw" },
  { bin: "fail2ban-client", installHint: "sudo apt install fail2ban" },
  { bin: "aa-status", installHint: "sudo apt install apparmor-utils" },
  { bin: "apt-get", installHint: null }, // ships with Debian/Ubuntu, not expected to be missing
];

export function registerCheckDependencies(server: McpServer) {
  server.registerTool(
    "system.check_dependencies",
    {
      description: "Checks OS compatibility and whether ufw/fail2ban/apparmor-utils are installed.",
      outputSchema: {
        ...checkResultShape,
        debianBased: z.boolean(),
        missing: z.array(z.object({ bin: z.string(), installHint: z.string() })),
      },
    },
    async () => {
      const isDebianBased = await checkDebianBased(); // reads /etc/os-release, checks ID_LIKE/ID for debian
      const missing = [];
      for (const { bin, installHint } of REQUIRED) {
        if (!(await commandExists(bin)) && installHint) missing.push({ bin, installHint });
      }
      const lines = [
        isDebianBased ? "OK: Debian-based OS" : "WARNING: not a Debian-based OS — v1 only supports Debian/Ubuntu",
        ...missing.map(m => `MISSING: ${m.bin} — install with: ${m.installHint}`),
      ];
      const summary = lines.join("\n");
      const structuredContent = {
        status: !isDebianBased ? "fail" : missing.length ? "warn" : "ok",
        summary,
        debianBased: isDebianBased,
        missing,
      };
      return { content: [{ type: "text", text: summary }], structuredContent };
    }
  );
}
```

The agent's job is just to relay `installHint` back to the user in plain language ("fail2ban isn't installed — run `sudo apt install fail2ban`, then try again") — no separate install-instructions system needed, the tool already returns the exact command. A client that reads `structuredContent` instead gets the same information as typed fields (`status`, `missing[]`) without having to parse the sentence.

Read-only checks all look the same:

```ts
// src/firewall.ts
import { z } from "zod";
import { checkResultShape } from "./schema.js";

export function registerFirewall(server: McpServer) {
  server.registerTool(
    "firewall.check_status",
    {
      description: "Lists open ports; flags anything besides 80/443.",
      outputSchema: { ...checkResultShape, openPorts: z.array(z.number()) },
    },
    async () => {
      const output = await run("ufw status");
      const openPorts = parsePorts(output);
      const bad = openPorts.filter(p => p !== 80 && p !== 443);
      const summary = bad.length
        ? `WARNING: unexpected ports open: ${bad.join(", ")}`
        : "OK: only 80/443 open";
      return {
        content: [{ type: "text", text: summary }],
        structuredContent: { status: bad.length ? "warn" : "ok", summary, openPorts },
      };
    }
  );
}
```

The app-hardening flow is two tools, generate then apply, kept separate so nothing is written without a distinct confirm step:

```ts
// src/apparmor.ts
server.registerTool(
  "apparmor.generate_profile",
  { description: "Builds an AppArmor profile for a project at the given restriction level.",
    inputSchema: { path: z.string(), type: z.enum(["web-service", "script", "background-service"]), level: z.enum(["low", "medium", "high"]) } },
  async ({ path, type, level }) => {
    const profile = buildProfile(path, type, level); // picks the template, fills in the path
    return { content: [{ type: "text", text: profile }] };
  }
);

server.registerTool(
  "apparmor.apply_profile",
  { description: "Loads a previously generated profile in complain mode, or enforce mode once confirmed.",
    inputSchema: { path: z.string(), mode: z.enum(["complain", "enforce"]), confirm: z.literal(true) } },
  async ({ path, mode }) => {
    await run(`apparmor_parser -r --${mode} ${path}/apparmor-profile`);
    return { content: [{ type: "text", text: `Applied in ${mode} mode.` }] };
  }
);
```

The deployment flow (§1, Use Case B) is three more tools in the same guarded style — a dedicated service account, a systemd unit that ties it to the loaded AppArmor profile plus optional resource limits, and a redeploy tool that never assumes who owns the project directory:

```ts
// src/serviceuser.ts
server.registerTool(
  "serviceuser.create",
  { description: "Creates a dedicated unprivileged Unix account for an app and re-owns its directory to it.",
    inputSchema: { path: z.string(), name: z.string(), confirm: z.literal(true) } },
  async ({ path, name }) => {
    if (!(await commandExists(name))) { // pseudocode: check via `id <name>` instead in the real impl
      await run(`useradd --system --no-create-home --shell /usr/sbin/nologin ${name}`);
    }
    await run(`chown -R ${name}:${name} ${path}`);
    return { content: [{ type: "text", text: `Service account ${name} owns ${path}.` }] };
  }
);
```

```ts
// src/systemd.ts
server.registerTool(
  "systemd.apply_unit",
  { description: "Writes and starts a systemd unit that runs the app as its service account under its AppArmor profile.",
    inputSchema: {
      name: z.string(), path: z.string(), user: z.string(), startCommand: z.string(),
      appArmorProfile: z.string(), cpuQuota: z.string().optional(), memoryMax: z.string().optional(),
      confirm: z.literal(true),
    } },
  async (input) => {
    const unitName = `deployguard-${input.name}`; // the naming convention apps.ts's listing depends on
    const unit = buildUnit({ ...input, unitName }); // User=/Group=/WorkingDirectory=/ExecStart=/AppArmorProfile=/CPUQuota=/MemoryMax=
    await run(`writefile /etc/systemd/system/${unitName}.service`, [unit]); // pseudocode for fs.writeFile
    await run("systemctl", ["daemon-reload"]);
    await run("systemctl", ["enable", "--now", unitName]);
    return { content: [{ type: "text", text: `${unitName}.service running as ${input.user}.` }] };
  }
);
```

```ts
// src/deploy.ts
server.registerTool(
  "deploy.update",
  { description: "Pulls and rebuilds an already-deployed app as its own service user, then restarts it.",
    inputSchema: { name: z.string(), path: z.string(), buildCommand: z.string().optional(), confirm: z.literal(true) } },
  async ({ name, path, buildCommand }) => {
    const owner = await getOwner(path); // `stat` the directory — the real owner, not a guessed name
    await run("runuser", ["-u", owner, "--", "bash", "-c", `cd ${path} && git pull && ${buildCommand ?? ""}`]);
    await run("systemctl", ["restart", `deployguard-${name}`]);
    return { content: [{ type: "text", text: `${name} redeployed and restarted as ${owner}.` }] };
  }
);
```

The lifecycle tools (§1, "managing a deployed app day-to-day") are thin `systemctl`/`journalctl` wrappers plus one shared helper (`parseUnitFile`, in `systemd.ts`) that both `apps.list` and `apps.update_limits` reuse instead of each re-parsing the installed unit file themselves:

```ts
// src/apps.ts
server.registerTool(
  "apps.list",
  { description: "Lists every application deployed by DeployGuard and its current status.",
    outputSchema: { ...checkResultShape, apps: z.array(z.object({
      name: z.string(), unit: z.string(), active: z.boolean(), enabled: z.boolean(),
      user: z.string(), path: z.string(), profile: z.string(),
    })) } },
  async () => {
    const unitFiles = await listUnitFiles("/etc/systemd/system", "deployguard-*.service");
    const apps = await Promise.all(unitFiles.map(async (unitFile) => {
      const fields = await parseUnitFile(unitFile); // from systemd.ts — User=/WorkingDirectory=/AppArmorProfile=
      const active = await isActive(fields.unitName);
      return { name: fields.unitName.replace(/^deployguard-/, ""), unit: fields.unitName, active, ...fields };
    }));
    const status = apps.some((a) => !a.active) ? "warn" : "ok";
    return { content: [{ type: "text", text: summarize(apps) }], structuredContent: { status, summary: summarize(apps), apps } };
  }
);

server.registerTool(
  "apps.get_logs",
  { description: "Gets recent logs for an app deployed by DeployGuard.",
    inputSchema: { name: z.string(), lines: z.number().optional() } },
  async ({ name, lines = 100 }) => {
    const logs = await run("journalctl", ["-u", `deployguard-${name}`, "-n", String(lines), "--no-pager"]);
    return { content: [{ type: "text", text: logs }], structuredContent: { logs } };
  }
);
```

```ts
// src/index.ts
const server = new McpServer({ name: "deployguard", version: "0.1.0" });
registerCheckDependencies(server);
registerFirewall(server);
registerFail2ban(server);
registerApt(server);
registerReport(server);
registerApparmor(server);
registerServiceUser(server);
registerSystemd(server);
registerDeploy(server);
registerApps(server);
await server.connect(new StdioServerTransport());
```

## 5. Getting Started

### Install

```bash
git clone <this-repo> deployguard-mcp
cd deployguard-mcp
npm install && npm run build
```

### Run it

```bash
node dist/index.js
```

It waits on stdio — that's expected. This just confirms it starts without errors.

### Point any AI agent at it

MCP is a standard protocol, so any client that supports MCP servers connects the same way: give it a command to launch the server.

**Claude Desktop / Claude Code** — add to the MCP config:

```json
{
  "mcpServers": {
    "deployguard": {
      "command": "node",
      "args": ["/absolute/path/to/deployguard-mcp/dist/index.js"]
    }
  }
}
```

**Any other MCP-compatible client or agent** — same idea: register a server named `deployguard` that launches via `node /absolute/path/to/deployguard-mcp/dist/index.js`. Not Claude-specific — any model or framework that speaks MCP can call these tools.

### Try it — dependency check

Ask the agent: *"Check if this server is ready for DeployGuard."* It calls `system.check_dependencies` first. If anything's missing (e.g. fail2ban isn't installed, or the OS isn't Debian-based), it tells you exactly what to run — e.g. `sudo apt install fail2ban` — and stops there until you've installed it.

### Try it — scan

Ask the agent: *"Run a security check on this server."* It calls `security.full_report` and returns a pass/warn summary across firewall, fail2ban, and APT sources. (`security.full_report` should itself call `system.check_dependencies` first and skip/flag any check whose tool is missing, rather than erroring.)

### Try it — deploy a project

Ask the agent: *"Deploy my Next.js app at `/var/www/myapp` with high restriction."* Expected flow:

1. Agent reads the project directory itself (entry point, start command, port).
2. Agent asks: "What restriction level — low, medium, or high?" (skip if already given, as above).
3. Agent calls `apparmor.generate_profile` and shows you the result.
4. You confirm, agent calls `apparmor.apply_profile` in `complain` mode, then `enforce` once satisfied.
5. Agent calls `serviceuser.create` (confirm) — creates the app's dedicated Unix account, re-owns the project directory.
6. Agent calls `systemd.generate_unit` and shows you the unit (start command, the AppArmor profile, any resource limits), then `systemd.apply_unit` (confirm) to write it, load the profile, and start the service.

### Try it — redeploy an update

Push a change to the app's repo, then ask: *"Redeploy myapp"* / *"deploy the latest update."* Expected flow:

1. Agent calls `deploy.update` (confirm) — pulls and rebuilds as the app's own service user (not root), then restarts the systemd unit.
2. Confirm the change is live, and that the pulled files are owned by the service account, not whoever ran the agent — that's the actual proof the DAC boundary held across a redeploy, not just at first deploy.

### Try it — manage deployed apps (list / stop / restart / remove / limits / logs)

Ask the agent: *"List all applications deployed by DeployGuard."* It calls `apps.list` and enumerates every `deployguard-*.service` unit with its status, service user, path, and AppArmor profile — including apps that are currently stopped, not just running ones.

Then try, against a real app name from that list:
- *"Stop myapp"* / *"restart myapp"* → `apps.stop` / `apps.restart` (confirm).
- *"Delete myapp"* → `apps.remove` (confirm) — removes the systemd unit only; confirm the project directory and service account are still there afterwards, since that's deliberate, not a bug.
- *"Limit myapp to 50% CPU and 512MB RAM"* → `apps.update_limits` (confirm) — confirm via `systemctl show deployguard-myapp --property=CPUQuotaPerSecUSec,MemoryMax` that the limit actually took effect.
- *"Show me myapp's logs"* → `apps.get_logs` (no confirm needed, read-only) — returns recent `journalctl` output for that unit.

## 6. What's Deliberately Left Out (for now)

- `firewall.enforce_baseline` and fail2ban jail-config suggestions — read-only for those two areas until the deployment flow (the main use case) is solid.
- `iptables`/`firewalld` support — `ufw` only in v1; add as new files alongside `firewall.ts` when needed.
- Non-Debian OS support (RHEL/Fedora/Arch/etc.) — `system.check_dependencies` should warn and stop rather than attempt unsupported package managers.
- No sudoers setup automation — if a command needs root, run the server as a user that already has the specific sudo rights it needs; document that per-command as it comes up.
- No fleet/multi-server support — one server, one host.
- No config files or allowlists yet (e.g. trusted APT repos) — hardcode a short list in `apt.ts` until it needs to be anything fancier.
- PM2 (or any other process manager) support — systemd is the only way DeployGuard-deployed apps run; see plan.md §3.5 for why.
- Multiple apps sharing one service account — one dedicated account per app for now, simpler DAC boundary; revisit only if account sprawl becomes a real problem.
- Resource type templates beyond `web-service` (`script`, `background-service`, `project-runtime` from plan.md §3.5.1) — added when a real use case needs them, same as the `iptables`/`firewalld` note above.
- Full teardown (`apps.remove` plus deleting the service account, project files, and AppArmor profile in one action) — `apps.remove` deliberately stays scoped to just the systemd unit; see plan.md §6 Open Questions.
- Structured/parsed log output — `apps.get_logs` returns raw `journalctl` text, no per-line parsing or filtering beyond `-n`/`--since`.
- Bulk operations across all apps at once (e.g. "restart everything DeployGuard manages") — each lifecycle tool takes one app name at a time.

Add any of the above only when a real use case needs it.
