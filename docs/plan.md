# Security Hardening MCP Server — Project Plan

## 1. Purpose

Build an MCP server that lets any AI/coding agent **check, monitor, enforce, and deploy** baseline Linux server security policy — without the agent needing shell access or manual `ssh`-ing in. The server reads system state, reports violations, and (where explicitly permitted) applies fixes.

Beyond auditing an already-running server, DeployGuard also **owns the deployment of an app from the start**: given a repo, it creates a dedicated service account (DAC), generates and loads an AppArmor profile (MAC), and runs the app under a systemd unit that ties both together plus optional CPU/RAM limits — replacing ad hoc process managers like PM2 for anything it deploys. It also handles **redeploying updates** to an app it manages, which is why this can't just be "generate a profile for an existing app": once a project directory is owned by its own service user, pulling new code has to happen *as that user*, not as root or whichever account is running the agent — see §3.5.

## 2. Core Policy Rules

| # | Rule | Enforced By |
|---|------|-------------|
| 1 | No ports should be open except 80 (and 443 if TLS is used) | Firewall check |
| 2 | No app/IP should be allowed to repeat failed actions (brute-force) indefinitely | fail2ban |
| 3 | No app should access files outside its own directory | AppArmor |
| 4 | System packages must only come from trusted repositories | APT source audit |

## 3. MCP Tools to Expose

### 3.1 `firewall.check_status`
- Reads `ufw status` / `iptables -L` / `firewalld` (auto-detect which is active).
- Returns list of open ports + rules.
- Flags **WARNING** for any open port other than 80/443.
- Optional `firewall.enforce_baseline` tool (gated, requires confirmation) to close disallowed ports.

### 3.2 `fail2ban.get_status`
- Reads `fail2ban-client status` and per-jail status (sshd, nginx, etc.).
- Returns active jails, ban counts, currently banned IPs.
- `fail2ban.check_installed` — warns if fail2ban isn't installed/running at all.
- Optional `fail2ban.suggest_jail_config` — recommends jail rules for detected services (ssh, nginx, custom app logs).

### 3.3 `apparmor.audit`
- Lists loaded AppArmor profiles and their mode (enforce/complain/unconfined).
- Flags any running process/app with **no profile** (i.e., unconfined) or with a profile that grants broad filesystem access outside its own app directory.
- `apparmor.check_root_permissions` — cross-checks running processes against `ps`/`systemd` to flag anything running as root/UID 0 that doesn't need to (e.g., a Node/PHP app process).
- `apparmor.generate_profile` — dynamically builds an AppArmor profile for a target resource (project, service, script, or application). See §3.5.1 for details.

### 3.4 `apt.audit_sources`
- Reads `/etc/apt/sources.list` and `/etc/apt/sources.list.d/*`.
- Cross-checks each repo against a maintained allowlist (Ubuntu/Debian official mirrors, well-known vendor repos e.g. NodeSource, Docker, PostgreSQL).
- Flags any repo not on the allowlist, and any repo missing GPG signature verification.
- `apt.list_installed_from_untrusted` — cross-references installed packages back to the repo they came from.
- *(Note: this is detection/reporting only for v1 — actual prevention, like an APT hook that blocks installs from untrusted repos at install-time, is a stretch goal noted in Open Questions.)*

### 3.5 Guided Secure Deployment (DAC + MAC + systemd)

Combines three independent layers instead of relying on AppArmor alone: a dedicated Unix service account per app (DAC — Discretionary Access Control), an AppArmor profile (MAC — Mandatory Access Control), and a systemd unit that ties both together plus enforces resource limits. systemd is the actual mechanism used to run and restart the app — this deliberately replaces PM2 (or any other process manager) for anything DeployGuard deploys, because PM2 can't natively express any of the three:

- Per-app resource limits (`CPUQuota=`, `MemoryMax=`) are real kernel cgroup enforcement, not something PM2 offers at all (`max_memory_restart` is reactive kill-and-restart, not a limit).
- Running each app as its own dedicated Unix user needs either a separate PM2 daemon per user or a `sudo -u` wrapper hack — systemd's `User=`/`Group=` directives do this natively.
- Binding an AppArmor profile to a process needs *something* to select the profile at launch (AppArmor can't tell two processes sharing the same interpreter binary apart on its own). systemd's native `AppArmorProfile=` directive (systemd ≥244; present on the Ubuntu 22.04 test VPS at systemd 249) does this in one line, without wrapping the start command in `aa-exec` or generating exec-transition wrapper scripts.

**Naming convention:** every unit DeployGuard creates is named `deployguard-<app-name>.service` — callers only ever supply the short app name; tools derive the full unit name internally. This is what makes §3.6's `apps.list` a reliable enumeration (`systemctl list-units 'deployguard-*'` / scanning `/etc/systemd/system/deployguard-*.service`) instead of a guess, the same way AppArmor profile names already carry a `deployguard.` prefix.

**`serviceuser.create`** — creates a dedicated, unprivileged system account for an app (`useradd --system --no-create-home --shell /usr/sbin/nologin <name>`; a no-op if it already exists, since redeploys reuse the same account) and re-owns the project directory to it (`chown -R`). Enforce-tier: requires confirmation, since this is real account creation and an ownership change, not read-only.

**`systemd.generate_unit`** — builds a systemd unit file (text only, not installed) from `{ name, path, user, startCommand, appArmorProfile, cpuQuota?, memoryMax? }`. The agent supplies `startCommand` from its own reading of the project (same principle as the original workflow below: DeployGuard doesn't parse `package.json` or detect frameworks itself).

**`systemd.apply_unit`** — writes the generated unit to `/etc/systemd/system/`, ensures the AppArmor profile it references is loaded (reuses `apparmor.apply_profile`, doesn't duplicate its logic), then `systemctl daemon-reload` + `enable --now`. Enforce-tier, requires confirmation, same complain-mode-first caution as AppArmor's own apply step.

**`deploy.update`** — redeploys a new version of an app DeployGuard already manages: looks up the project directory's actual owning user (`stat` the path — the real owner is the source of truth, not a naming convention), then pulls and builds **as that service user** via `runuser -u <owner> --`, never as root or whichever account is running the agent, since pulling files as the wrong owner would silently break the DAC isolation `serviceuser.create` set up. Restarts the systemd unit on success. Enforce-tier, requires confirmation — this pulls and executes remote repository content.

#### 3.5.1 `apparmor.generate_profile` — Dynamic Profile Generation

Input: resource path/name, **resource type**, and **security level**. Output: a ready-to-load AppArmor profile (`.load`-able via `apparmor_parser`), not yet applied unless enforcement is confirmed.

**Resource type** determines the base rule template (each type has different legitimate needs):
- `script` (bash/python/node script run standalone)
- `web-service` (nginx/apache/node/php app bound to a port)
- `background-service` (systemd daemon, worker, cron job)
- `project-runtime` (interpreter/runtime dir, e.g. a whole app folder with its own venv/node_modules)

**Security level** determines how far permissions are dialed back:

| Level | Filesystem | Network | System commands | Capabilities |
|-------|-----------|---------|------------------|--------------|
| **Low** | Read/write own dir + common shared libs/config paths | Allowed | Allowed (e.g. can shell out) | Broad, except explicitly denied critical ones (no raw disk, no kernel modules, no `/etc/shadow` writes) |
| **Medium** | Read/write own dir + explicitly declared dependency paths only | Restricted to declared ports/hosts | Only an allow-listed set (e.g. `git`, `node`, package manager for that stack) | Minimal, no admin capabilities |
| **High** | Read/write **own directory only** (deny-by-default on everything else) | Only the specific bind port declared, no outbound unless declared | None — no `exec` of arbitrary system binaries | None — no `CAP_SYS_ADMIN`, no `CAP_NET_ADMIN`, no setuid |

Regardless of level, the profile **always** denies:
- Writing to system-critical paths (`/etc/passwd`, `/etc/shadow`, `/boot`, kernel modules).
- Escalation capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SETUID` unless the resource type genuinely requires it, e.g. a package manager itself).

Workflow (revised — see §3.5 above for how the profile gets bound to a process):
1. Agent calls `apparmor.generate_profile` with `{ path, type, level }`.
2. Tool inspects the resource (what interpreter, what ports it binds, what config files it reads) to auto-fill the dependency list, then applies the level's restriction template. *(Simplified in the current implementation to filling the template with the project path only — see implementation-flow.md Stage 5.)*
3. Returns the generated profile text + a diff/summary of what it allows and denies, for the user to review.
4. `apparmor.apply_profile` (enforce-tier) loads it in `complain` mode first, then `enforce` mode after user confirms no false-positive breakage — but loading the profile alone doesn't confine anything until a systemd unit's `AppArmorProfile=` (§3.5) actually references it.

### 3.6 App Lifecycle Management (list / stop / restart / remove / limits / logs)

The PM2-equivalent day-2 surface, once an app has been deployed per §3.5 — this is what makes "list all applications deployed by deployguard" or "stop myapp" answerable at all, since it's what actually enumerates and controls the `deployguard-*.service` units §3.5 created.

**`apps.list`** — enumerates every `deployguard-*.service` unit (scans `/etc/systemd/system/deployguard-*.service`, not just currently-running ones, so a stopped app still shows up) and reports, per app: name, unit state (active/inactive/failed), enabled/disabled, service user, project path, and AppArmor profile — the last three parsed back out of the installed unit file's `User=`/`WorkingDirectory=`/`AppArmorProfile=` lines. Read-only, extends `checkResultShape`: `warn` if any listed app isn't active, `ok` otherwise (zero apps found is `ok`, not a failure — that's just "nothing deployed yet").

**`apps.stop`** / **`apps.restart`** — `systemctl stop|restart deployguard-<name>.service`. Enforce-tier, requires confirmation (these affect a live, possibly user-facing service).

**`apps.remove`** — stops, disables, and deletes the unit file (`daemon-reload` after). Enforce-tier, requires confirmation. **Deliberately scoped**: does *not* delete the project directory, the service user, or the AppArmor profile — those are separate, more destructive actions this tool does not perform unless a dedicated teardown tool is built later (see §6 Open Questions). Removing the systemd unit is reversible (regenerate + reapply); deleting a service account or a project's files is not.

**`apps.update_limits`** — edits an already-deployed app's `CPUQuota=`/`MemoryMax=` without needing a separate metadata store: reads the installed unit file back, parses out its existing `User=`/`WorkingDirectory=`/`ExecStart=`/`AppArmorProfile=`, rebuilds the unit via the same template `systemd.generate_unit` uses with the new limit values substituted in, rewrites, `daemon-reload` + restart. The unit file itself is the source of truth — no new state to keep in sync. Enforce-tier, requires confirmation.

**`apps.get_logs`** — wraps `journalctl -u deployguard-<name>.service -n <lines> --no-pager` (optional `--since`), returns the raw log text. Read-only — no confirmation needed, reading logs has no side effects. `outputSchema` is just `{ logs: z.string() }`, same non-`checkResultShape` pattern as `apparmor.generate_profile` (this isn't a pass/fail judgment either).

### 3.7 `security.full_report`
- Aggregator tool — runs all four read-only checks and returns one consolidated pass/warn/fail report the agent can present to the user or act on.

## 4. Architecture

- **MCP server** (Node or Python) exposing the tools above over stdio/SSE, installed on the target Linux server itself (or reachable via SSH from a control host — decide in Phase 1).
- Each tool = thin wrapper around existing CLI tools (`ufw`, `fail2ban-client`, `aa-status`, `apt-cache policy`, `useradd`, `systemctl`, `journalctl`) — parse their output, don't reimplement the security logic.
- **Read-only by default.** Any tool that changes system state (closing a port, writing an AppArmor profile, creating a service account, writing/loading/editing/deleting a systemd unit, pulling and building an app's code, stopping/restarting a service) is a separate "enforce" tool, clearly named, and requires an explicit confirm flag from the calling agent/user — no silent enforcement. `apps.list` and `apps.get_logs` (§3.6) are the exceptions that stay read-only, same as any other read-only check — listing units and reading logs have no side effects.
- Runs with least privilege needed: ideally a `sudoers` entry scoped to only the specific read commands (and specific enforce commands), not blanket root. Note the §3.5/§3.6 deployment and lifecycle tools (`serviceuser.create`, `systemd.apply_unit`, `deploy.update`, `apps.stop`/`restart`/`remove`/`update_limits`) need a **wider** privilege tier than the read-only checks — creating Unix accounts, `chown`'ing arbitrary paths, writing `/etc/systemd/system/`, running `systemctl` and `runuser` — so scope their `sudoers` entries separately from the read-only tools' narrower ones rather than granting one entry that covers both.
- The deployment flow (§3.5) deliberately does not reimplement framework detection: the calling agent reads the target project itself (`package.json`, entry point, port) and supplies the build/start commands as tool input, the same principle the original guided-hardening workflow already used.
- `apps.list` and `apps.update_limits` both need to parse an installed unit file's fields back out (`User=`, `WorkingDirectory=`, `AppArmorProfile=`, etc.) — this parsing lives in one shared helper in `systemd.ts`, not duplicated in `apps.ts`, the same way `apparmor.ts`'s `profileFilePath` helper is already shared rather than reimplemented per caller.

## 5. Phases

**Phase 1 — Read-only visibility**
Implement `firewall.check_status`, `fail2ban.get_status`, `apparmor.audit`, `apt.audit_sources`, and `security.full_report`. No enforcement yet. Goal: an agent can generate a trustworthy security posture report.

**Phase 2 — AppArmor profile generation & guarded load**
Add `apparmor.generate_profile` (text-only) and `apparmor.apply_profile` (loads into the kernel via `apparmor_parser`, complain-mode first). Loading a profile here doesn't yet confine any process — that requires a systemd unit to reference it (Phase 3).

**Phase 3 — Guided Secure Deployment (DAC + MAC + systemd)**
Add `serviceuser.create`, `systemd.generate_unit`, and `systemd.apply_unit` per §3.5. This is what turns a generated AppArmor profile into something actually enforced against a real running process, and gives each app its own Unix account and (optionally) resource limits.

**Phase 4 — Deploy Updates**
Add `deploy.update` per §3.5 — pulls and rebuilds an already-deployed app as its own service user, then restarts its systemd unit. Depends on Phase 3 having created the service account and unit already.

**Phase 5 — App Lifecycle Management**
Add `apps.list`, `apps.stop`, `apps.restart`, `apps.remove`, `apps.update_limits`, `apps.get_logs` per §3.6. Depends on Phase 3's `deployguard-*.service` naming convention existing already. This is what makes "list/stop/restart/delete an app, like PM2" and "show me myapp's logs" answerable.

**Phase 6 — Guarded misc enforcement**
`firewall.enforce_baseline` and fail2ban jail-config suggestions — unrelated to the deployment flow, lower priority than it, all still requiring explicit confirmation input.

**Phase 7 — Continuous monitoring**
Add a polling/webhook mode so the MCP server can push alerts (e.g., new port opened, new unconfined app detected, untrusted repo added) rather than only responding to pull requests.

**Phase 8 — APT install-time prevention (stretch)**
Investigate an APT hook (`Pre-Install-Pkgs` / `apt-listchanges`) or a wrapper policy that blocks `apt-get install` from non-allowlisted repos at the moment of install, rather than just auditing after the fact.

## 6. Open Questions

- Where does the MCP server run — locally on the same VPS, or as a control-plane process that SSHes into managed servers?
- What's the source of truth for the "trusted repo allowlist" — hardcoded, config file, or fetched from a maintained list?
- How to safely test AppArmor profile generation and the systemd deploy flow without breaking a running app (staging environment needed).
- Multi-server support: single-server tool now, or design the schema for fleet management from day one?
- Multiple apps per service account, or strictly one account per app? Current design assumes one dedicated account per app (simpler DAC boundary); revisit if that turns out to be too many accounts for a busy box.
- Is a full teardown tool (delete the service account + project files + AppArmor profile in one action, beyond what `apps.remove` does) ever wanted, or is "unit removed, everything else left in place" the right permanent default? `apps.remove`'s current scoping treats the more destructive version as a deliberately separate, not-yet-built action.

## 7. Out of Scope (v1)

- Full IDS/IPS replacement (this wraps existing tools, doesn't reinvent them).
- Windows/macOS support.
- Automatic untrusted-package removal (audit/report only, per Phase 7 note above).
- PM2 (or any other process manager) as the thing DeployGuard-deployed apps run under — deliberately replaced by systemd per §3.5, since PM2 can't natively express per-app resource limits or per-app Unix accounts the way systemd does.
- Framework/build-tool auto-detection inside DeployGuard tools (parsing `package.json`, guessing the start command) — the calling agent reads the project and supplies these as explicit input, per §4.
