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

## Stage 6 — AppArmor Apply (Guarded)

**Goal:** close the loop on Use Case B — actually load the profile, safely.

24. Write `apparmor.apply_profile` with input `{ path, mode: "complain" | "enforce", confirm: true }` — calls `apparmor_parser -r --<mode>`. `outputSchema` extends `checkResultShape` with `mode`.
25. Wire the `confirm: true` requirement so the tool call fails fast without it (no separate confirm-gate module needed at this size — a required literal field in the schema is enough).
26. **Check:** on a disposable test project — generate a profile, apply in `complain` mode, exercise the app, confirm no unexpected denials in `dmesg`/`journalctl`, then apply in `enforce` mode and re-verify the app still works.

## Stage 7 — Full Guided Flow, End to End

**Goal:** validate Use Case B exactly as a real user would run it — this is the actual product, not just its parts.

27. Point a connected agent at a real (or disposable) Next.js project directory and ask it to "secure this app."
28. Confirm the agent: reads the project unprompted, asks for a restriction level, calls `generate_profile`, shows you the result, asks for confirmation, applies in `complain` mode, then asks again before `enforce`.
29. Fix whatever's awkward in the tool descriptions/output — this is where you'll discover if a tool's returned text is confusing to the model, not in the code review.

## What Comes After This

Once Stages 0–7 are done, v1 is complete per [mcp-server-implementation.md](mcp-server-implementation.md#6-whats-deliberately-left-out-for-now). Do not start these until there's a real need:

- `firewall.enforce_baseline` (closing ports directly)
- `iptables`/`firewalld` adapters alongside `ufw`
- fail2ban jail-config suggestions
- Non-Debian OS support
- Config-file-driven APT allowlist
- Fleet/multi-server support
