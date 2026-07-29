# DeployGuard MCP Server — Implementation Flow

A sequenced task list for building the server described in [mcp-server-implementation.md](mcp-server-implementation.md). Each task is small enough to finish and test in one sitting, and later tasks depend only on earlier ones — work top to bottom.

**Standing rule, applies to every tool in every stage below, not just Stage 1:** write each tool's `description` in the language a user would actually use to ask for it ("is this server ready," "what ports are open"), not a description of its internals. Confirmed by testing: an agent asked a generic question with no mention of DeployGuard by name will otherwise burn time reading through project files trying to disambiguate intent before it even considers a tool call — a good description is what lets it go straight to the tool instead. See [mcp-server-implementation.md §4, "Discoverability"](mcp-server-implementation.md#4-tool-pattern) for the concrete before/after and the companion server-level `instructions` field.

## Stage 0 — Project Skeleton

**Goal:** an MCP server that starts, connects, and exposes zero tools. Proves the plumbing works before any security logic exists.

1. `npm init`, install `@modelcontextprotocol/sdk`, `zod`, TypeScript. Set up `tsconfig.json` + build script.
2. Write `src/exec.ts` — one function, `run(command: string, args: string[])`, that shells out via `execFile` (never a raw shell string) and returns stdout/stderr/exit code. Every tool from here on goes through this.
3. Write `src/schema.ts` — the shared `{ status: "ok"|"warn"|"fail", summary: string }` shape (`checkResultShape`) every tool's `outputSchema` extends. This is what keeps tool results machine-parseable (`structuredContent`) instead of relying on each client's model to consistently re-derive structure from prose — see [mcp-server-implementation.md §4](mcp-server-implementation.md#4-tool-pattern). Foundational plumbing, same tier as `exec.ts`, even though no tool uses it yet.
4. Write `src/index.ts` — construct `McpServer` with a top-level `instructions` string (standing guidance like "for questions about this host's security status, prefer these tools over reading source files"), connect `StdioServerTransport`, register nothing yet. Same discoverability motivation as the tool-description rule above, just server-wide instead of per-tool — update this string as tools are added in later stages, it's living text, not a one-time Stage 0 artifact.
5. **Check:** `node dist/index.js` starts and idles on stdio without crashing.
6. Connect it to Claude Desktop/Code per the getting-started guide and confirm the client sees a server named `deployguard` with no tools — confirms the client-side wiring before there's anything interesting to call.

## Stage 1 — Dependency Check

**Goal:** the server can tell the user what's missing before anything else is attempted. Everything after this stage assumes it exists.

7. Write `src/deps.ts`: `checkDebianBased()` (reads `/etc/os-release`), `commandExists(bin)` (tries `which <bin>`), and the `REQUIRED` list (`ufw`, `fail2ban-client`, `aa-status`).
8. Register `system.check_dependencies` in `index.ts`, with an `outputSchema` extending `checkResultShape` (`debianBased`, `missing[]`) and returning matching `structuredContent` alongside the existing `content` text. Write the `description` per the standing rule above — phrase it around "is this server/host ready," not just "checks whether ufw/fail2ban/apparmor-utils are installed."
9. **Check:** run it on a real Debian/Ubuntu box with something intentionally missing (e.g. uninstall fail2ban) — confirm the tool reports the exact `apt install` command, and reports OK once installed. Also call the tool directly via an MCP client (not just through an agent's chat reply) and confirm `structuredContent` validates against `outputSchema` and matches the real host state — this is the check that's independent of how any given agent chooses to narrate the result. Then, from a working directory that isn't this repo, ask the connected agent a generic question ("is this server ready?") **without** naming DeployGuard or the tool — confirm it calls the tool directly instead of exploring files first; that's the description/instructions actually earning their keep.

## Stage 2 — First Read-Only Check: Firewall

**Goal:** one full check end-to-end (CLI call → parse → pass/warn output), proving the pattern before repeating it three more times.

10. Write `src/firewall.ts`: run `ufw status`, parse allowed ports, flag anything besides 80/443.
11. Register `firewall.check_status` with an `outputSchema` extending `checkResultShape` (`openPorts[]`), returning matching `structuredContent`.
12. **Check:** ask the connected agent "what ports are open on this server?" — confirm it calls the tool and returns a sensible answer against your actual `ufw` rules.

## Stage 3 — Remaining Read-Only Checks

**Goal:** the other three individual checks from plan.md, each following the exact pattern proven in Stage 2. These three can be done in any order, independently.

13. `src/fail2ban.ts` → `fail2ban.get_status` (active jails, ban counts) — `outputSchema` extends `checkResultShape` with `jails[]`.
14. `src/apt.ts` → `apt.audit_sources` (parse `/etc/apt/sources.list*`, check against a short hardcoded allowlist) — `outputSchema` extends `checkResultShape` with `untrustedSources[]`.
15. `src/apparmor.ts` (audit half only for now) → `apparmor.audit` (loaded profiles + enforce/complain/unconfined mode) — `outputSchema` extends `checkResultShape` with `profiles[]`.
16. **Check:** each tool called individually returns a correct result against the real host state, and each result's `structuredContent` validates against its `outputSchema`.

## Stage 4 — Aggregate Report

**Goal:** the single entry point most agents will actually call.

17. Write `src/report.ts`: `security.full_report` calls `system.check_dependencies` first, then each of the four checks (skipping/flagging ones whose CLI tool is missing), and concatenates results into one pass/warn/fail summary. `outputSchema` extends `checkResultShape` with `checks: Array<{ name, status, summary }>` — the per-check `structuredContent` results collected, not just their text.
18. Register it.
19. **Check:** ask the agent "run a security check on this server" — confirm one clean consolidated answer. This closes out **Use Case A (ad-hoc scan)** end-to-end.

## Stage 5 — AppArmor Profile Generation

**Goal:** the first half of the app-hardening flow — produce a profile, don't apply it yet.

20. Design the three level templates (low/medium/high) as plain functions in `apparmor.ts` per plan.md §3.3.1 — start with just the `web-service` resource type, since that's the Next.js use case.
21. Write `buildProfile(path, type, level)` — fills the template with the project path.
22. Register `apparmor.generate_profile` with input `{ path, type, level }`. This tool produces a profile rather than a pass/warn/fail judgment, so it doesn't extend `checkResultShape` — `outputSchema` is just `{ profile: z.string() }`.
23. **Check:** call it against a real project directory, read the generated profile text by eye — does it look like a sane AppArmor profile, does the low/medium/high difference actually show up in the output?

## Stage 6 — AppArmor Apply (Guarded, Load-Only)

**Goal:** load a generated profile into the kernel, safely. Binding it to an actual running process is no longer this tool's job — that's Stage 8, via systemd's own `AppArmorProfile=` directive, not `aa-exec` or exec-transition wrapper scripts (see plan.md §3.5 for why that idea was dropped: it can't scope a profile to one app when multiple apps share the same interpreter binary).

24. Write `apparmor.apply_profile` with input `{ path, mode: "complain" | "enforce", confirm: true }` — calls `apparmor_parser -r --<mode>` against the profile file at `profileFilePath(path)`. `outputSchema` extends `checkResultShape` with `mode`.
25. Wire the `confirm: true` requirement so the tool call fails fast without it (no separate confirm-gate module needed at this size — a required literal field in the schema is enough).
26. **Check:** load a generated profile in `complain` mode, confirm no unexpected denials in `dmesg`/`journalctl`, then apply in `enforce` mode. Since nothing is bound to a process yet, this check only confirms the profile loads without a syntax error — real enforcement behavior gets verified once a systemd unit references it in Stage 8.

## Stage 7 — Dedicated Service User (DAC)

**Goal:** give each deployed app its own unprivileged Unix account, so file-ownership isolation between apps doesn't depend on AppArmor being correctly configured — a second, independent layer per plan.md §3.5. This has to exist before Stage 8's systemd unit, since the unit's `User=`/`Group=` reference this account.

27. Write `src/serviceuser.ts`: `serviceuser.create` with input `{ path, name, confirm: true }` — checks whether the account already exists (`id <name>`) and skips creation if so (redeploys reuse the same account, this must be a safe no-op), otherwise runs `useradd --system --no-create-home --shell /usr/sbin/nologin <name>`, then always `chown -R <name>:<name> <path>`.
28. Register the tool with `outputSchema` extending `checkResultShape` with `username`. Enforce-tier: requires `confirm: true`, same pattern as `apparmor.apply_profile`.
29. **Check:** run against a disposable test directory — confirm the user is created (`id <name>`) and the directory is re-owned (`stat` shows the new owner); run it a second time and confirm it's a safe no-op, not an error, since Stage 9's redeploy flow depends on that.

## Stage 8 — systemd Unit: Generate + Apply

**Goal:** the piece that actually ties DAC + MAC + resource limits together — this is what runs the app, replacing PM2 or any other process manager for anything DeployGuard deploys.

30. Write `src/systemd.ts`: `buildUnit({ name, path, user, startCommand, appArmorProfile, cpuQuota?, memoryMax? })` — a template function (same shape as `buildProfile` in `apparmor.ts`) producing unit file text with `User=`, `Group=`, `WorkingDirectory=`, `ExecStart=`, `AppArmorProfile=`, and the optional resource-limit directives. `startCommand` is supplied by the calling agent, same principle as `apparmor.generate_profile`'s `path` — DeployGuard doesn't parse `package.json` or detect frameworks itself. The tool always derives the actual unit name as `deployguard-<name>` — callers only ever pass the short app name, never the full unit filename, so Stage 10's `apps.list` can reliably enumerate by the `deployguard-*` prefix.
31. Register `systemd.generate_unit` — text-only, mirrors `apparmor.generate_profile`: input `{ name, path, user, startCommand, appArmorProfile, cpuQuota?, memoryMax? }`, `outputSchema` is just `{ unit: z.string() }`, no write, no `systemctl` call.
32. Register `systemd.apply_unit` — input adds `confirm: true`. Writes the unit to `/etc/systemd/system/deployguard-<name>.service`, ensures the referenced AppArmor profile is loaded (reuse `apparmor.apply_profile`'s logic instead of re-implementing it), then `systemctl daemon-reload` + `systemctl enable --now deployguard-<name>`. `outputSchema` extends `checkResultShape`. Also write `parseUnitFile(unitFile)` here (not in a new file) — reads an installed unit back into `{ user, path, startCommand, appArmorProfile, cpuQuota?, memoryMax? }`, since Stage 10's `apps.list` and `apps.update_limits` both need this and shouldn't duplicate it.
33. **Check:** on a disposable Next.js project — generate the unit, review it, apply it, confirm `systemctl status deployguard-<name>` shows it running as the service user; confirm `aa-status` now lists the process under the profile, not unconfined (this is the first real end-to-end confinement check, since Stage 6 alone couldn't prove it); and if you set `CPUQuota=`/`MemoryMax=`, confirm it's visible via `systemctl show deployguard-<name> --property=CPUQuotaPerSecUSec,MemoryMax`.

## Stage 9 — Deploy Updates (Redeploy Flow)

**Goal:** the ongoing half of the product, not just first deploy — pulling new commits without breaking the DAC boundary Stage 7 set up.

34. Write `src/deploy.ts`: `deploy.update` with input `{ name, path, buildCommand?, confirm: true }`. Look up the directory's actual owning user via `stat` (the real owner is the source of truth — don't assume a naming convention matches), then run `runuser -u <owner> -- bash -c "cd <path> && git pull && <buildCommand>"` — **never as root or the calling SSH/agent user**, since files pulled under the wrong owner would silently break the isolation Stage 7 set up.
35. After a successful pull+build, `systemctl restart <name>`.
36. `outputSchema` extends `checkResultShape`, capturing the pull/build output so the agent can show it on failure rather than swallowing a failed `git pull` or build error.
37. **Check:** commit a real change to a disposable test app's repo, run `deploy.update`, confirm the change is live — and confirm the pulled files are owned by the service user, not root or whoever ran the agent. That ownership check is the one that actually proves the DAC boundary survived a redeploy, not just the initial deploy.

## Stage 10 — App Lifecycle Management

**Goal:** the PM2-equivalent day-2 surface — list, stop, restart, remove, adjust resource limits, and read logs for anything DeployGuard has deployed. Depends on Stage 8's `deployguard-<name>` naming convention and `parseUnitFile` helper already existing.

38. Write `src/apps.ts`: `apps.list` — scans `/etc/systemd/system/deployguard-*.service` (not just currently-running units, so a stopped app still shows up), calls `parseUnitFile` (from `systemd.ts`) plus `systemctl is-active`/`is-enabled` per unit. `outputSchema` extends `checkResultShape` with `apps: Array<{ name, unit, active, enabled, user, path, profile }>` — `warn` if any app isn't active, `ok` otherwise (zero apps is `ok`, not a failure).
39. Register `apps.stop` and `apps.restart` — `{ name, confirm: true }`, call `systemctl stop|restart deployguard-<name>`. `outputSchema` extends `checkResultShape`.
40. Register `apps.remove` — `{ name, confirm: true }`, calls `systemctl stop`, `systemctl disable`, deletes the unit file, `daemon-reload`. **Scope this deliberately narrow**: don't delete the project directory, service account, or AppArmor profile — those are separate, harder-to-reverse actions, not this tool's job (see plan.md §6 Open Questions on whether a fuller teardown tool is ever wanted).
41. Register `apps.update_limits` — `{ name, cpuQuota?, memoryMax?, confirm: true }`: `parseUnitFile` the installed unit, rebuild via `buildUnit` with the new limit values substituted in (keeping the existing `user`/`path`/`startCommand`/`appArmorProfile`), rewrite, `daemon-reload`, restart. No new state store — the installed unit file is the only source of truth.
42. Register `apps.get_logs` — `{ name, lines?: number, since?: string }`, wraps `journalctl -u deployguard-<name> -n <lines> --no-pager [--since <since>]`. Read-only, no `confirm` field at all — `outputSchema` is just `{ logs: z.string() }`, same non-`checkResultShape` pattern as `apparmor.generate_profile`.
43. **Check:** against a disposable deployed app — `apps.list` shows it; `apps.stop` then `apps.list` again shows it as inactive (not missing — this is the check that `apps.list` scans installed units, not just running ones); `apps.restart` brings it back; `apps.update_limits` with a new `MemoryMax=` is visible via `systemctl show`; `apps.get_logs` returns real `journalctl` output; `apps.remove` deletes the unit but leaves the project directory and service account (`id <user>`) intact — verify that last part explicitly, since it's the one a careless implementation would get wrong.

## Stage 11 — Full Guided Flow, End to End

**Goal:** validate the real product — deploying a fresh app securely, redeploying it, and managing it day-to-day — exactly as a real user would ask for it.

44. Point a connected agent at a real (or disposable) Next.js project's Git repo and ask it to **"deploy this application with high restriction."**
45. Confirm the agent: reads the project unprompted (to determine the start command), asks for a restriction level if not given, then in order — `apparmor.generate_profile` → shows the result → confirms → `apparmor.apply_profile` (complain, then enforce) → `serviceuser.create` (confirm) → `systemd.generate_unit` → shows the unit → confirms → `systemd.apply_unit` (confirm).
46. Push a real change to the app's repo and ask the agent to **"deploy the latest update."** Confirm it calls `deploy.update` rather than a manual `git pull` over a shell tool, and that the app comes back up running as the same service user under the same profile.
47. Ask **"list all applications deployed by DeployGuard"** — confirm `apps.list` is called (not the agent trying to reconstruct this via raw `systemctl`/`ps` shell commands) and the deployed app shows up correctly. Then ask to stop it, restart it, set a resource limit, and show its logs — confirm each maps to the right `apps.*` tool, not a manual shell command.
48. Fix whatever's awkward in the tool descriptions/output — same rule as every earlier stage's check: this is where model confusion actually surfaces, not in code review.

## What Comes After This

Once Stages 0–11 are done, v1 is complete per [mcp-server-implementation.md](mcp-server-implementation.md#6-whats-deliberately-left-out-for-now). Do not start these until there's a real need:

- `firewall.enforce_baseline` (closing ports directly)
- `iptables`/`firewalld` adapters alongside `ufw`
- fail2ban jail-config suggestions
- Non-Debian OS support
- Config-file-driven APT allowlist
- Fleet/multi-server support
- PM2 support as an alternative to the systemd-based deploy flow — deliberately dropped in favor of systemd, see plan.md §3.5.
- Framework/build-tool auto-detection inside a DeployGuard tool (parsing `package.json`, guessing a start command) — the agent reads the project and supplies these explicitly, same as it already does for `apparmor.generate_profile`'s `path`.
- Resource type templates beyond `web-service` (`script`, `background-service`, `project-runtime`) — new template functions added when a real use case needs them, not upfront.
- Multiple apps sharing one service account — one dedicated account per app for now.
- Full teardown (deleting the service account, project files, and AppArmor profile alongside the unit) — `apps.remove` deliberately stays scoped to just the systemd unit.
- Structured/parsed log output from `apps.get_logs` — raw `journalctl` text only.
- Bulk operations across all deployed apps at once — every lifecycle tool takes one app name at a time.
