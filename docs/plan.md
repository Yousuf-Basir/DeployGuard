# Security Hardening MCP Server — Project Plan

## 1. Purpose

Build an MCP server that lets any AI/coding agent **check, monitor, and enforce** baseline Linux server security policy — without the agent needing shell access or manual `ssh`-ing in. The server reads system state, reports violations, and (where explicitly permitted) applies fixes.

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
- `apparmor.generate_profile` — dynamically builds an AppArmor profile for a target resource (project, service, script, or application). See §3.3.1 for details.

#### 3.3.1 `apparmor.generate_profile` — Dynamic Profile Generation

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

Workflow:
1. Agent calls `apparmor.generate_profile` with `{ path, type, level }`.
2. Tool inspects the resource (what interpreter, what ports it binds, what config files it reads) to auto-fill the dependency list, then applies the level's restriction template.
3. Returns the generated profile text + a diff/summary of what it allows and denies, for the user to review.
4. A separate `apparmor.apply_profile` (enforce-tier tool) loads it in `complain` mode first, then `enforce` mode after user confirms no false-positive breakage.

### 3.4 `apt.audit_sources`
- Reads `/etc/apt/sources.list` and `/etc/apt/sources.list.d/*`.
- Cross-checks each repo against a maintained allowlist (Ubuntu/Debian official mirrors, well-known vendor repos e.g. NodeSource, Docker, PostgreSQL).
- Flags any repo not on the allowlist, and any repo missing GPG signature verification.
- `apt.list_installed_from_untrusted` — cross-references installed packages back to the repo they came from.
- *(Note: this is detection/reporting only for v1 — actual prevention, like an APT hook that blocks installs from untrusted repos at install-time, is a stretch goal noted in Open Questions.)*

### 3.5 `security.full_report`
- Aggregator tool — runs all four checks and returns one consolidated pass/warn/fail report the agent can present to the user or act on.

## 4. Architecture

- **MCP server** (Node or Python) exposing the tools above over stdio/SSE, installed on the target Linux server itself (or reachable via SSH from a control host — decide in Phase 1).
- Each tool = thin wrapper around existing CLI tools (`ufw`, `fail2ban-client`, `aa-status`, `apt-cache policy`) — parse their output, don't reimplement the security logic.
- **Read-only by default.** Any tool that changes system state (closing a port, writing an AppArmor profile, banning an IP) is a separate "enforce" tool, clearly named, and requires an explicit confirm flag from the calling agent/user — no silent enforcement.
- Runs with least privilege needed: ideally a `sudoers` entry scoped to only the specific read commands (and specific enforce commands), not blanket root.

## 5. Phases

**Phase 1 — Read-only visibility**
Implement `firewall.check_status`, `fail2ban.get_status`, `apparmor.audit`, `apt.audit_sources`, and `security.full_report`. No enforcement yet. Goal: an agent can generate a trustworthy security posture report.

**Phase 2 — Guarded enforcement**
Add `firewall.enforce_baseline`, `apparmor.generate_profile_template`, and jail-config suggestions. All require explicit confirmation input.

**Phase 3 — Continuous monitoring**
Add a polling/webhook mode so the MCP server can push alerts (e.g., new port opened, new unconfined app detected, untrusted repo added) rather than only responding to pull requests.

**Phase 4 — APT install-time prevention (stretch)**
Investigate an APT hook (`Pre-Install-Pkgs` / `apt-listchanges`) or a wrapper policy that blocks `apt-get install` from non-allowlisted repos at the moment of install, rather than just auditing after the fact.

## 6. Open Questions

- Where does the MCP server run — locally on the same VPS, or as a control-plane process that SSHes into managed servers?
- What's the source of truth for the "trusted repo allowlist" — hardcoded, config file, or fetched from a maintained list?
- How to safely test AppArmor profile generation without breaking a running app (staging environment needed).
- Multi-server support: single-server tool now, or design the schema for fleet management from day one?

## 7. Out of Scope (v1)

- Full IDS/IPS replacement (this wraps existing tools, doesn't reinvent them).
- Windows/macOS support.
- Automatic untrusted-package removal (audit/report only, per Phase 4 note above).
