import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { runChecked } from "./exec.js";
import { checkResultShape } from "./schema.js";

export interface ServiceUserResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  username: string;
  [key: string]: unknown;
}

async function userExists(name: string): Promise<boolean> {
  const { code } = await runChecked("id", [name]);
  return code === 0;
}

// Stage 7 (DAC): a dedicated, unprivileged system account per app, so
// file-ownership isolation between apps doesn't depend on AppArmor (Stage
// 5/6) being correctly configured — a second, independent layer per
// plan.md §3.5. Stage 8's systemd unit references this account's name via
// User=/Group=, so it must exist (and own the project dir) before that.
export async function createServiceUser(path: string, name: string): Promise<ServiceUserResult> {
  const existed = await userExists(name);

  if (!existed) {
    const { code, stderr } = await runChecked("useradd", [
      "--system",
      "--no-create-home",
      "--shell",
      "/usr/sbin/nologin",
      name,
    ]);
    if (code !== 0) {
      return {
        status: "fail",
        summary: `FAIL: could not create service account ${name}: ${stderr.trim() || "unknown error"}`,
        username: name,
      };
    }
  }

  const { code, stderr } = await runChecked("chown", ["-R", `${name}:${name}`, path]);
  if (code !== 0) {
    return {
      status: "fail",
      summary: `FAIL: service account ${name} exists but could not re-own ${path}: ${stderr.trim() || "unknown error"}`,
      username: name,
    };
  }

  return {
    status: "ok",
    summary: existed
      ? `OK: service account ${name} already existed (reused for redeploy) — ${path} is owned by it.`
      : `OK: created service account ${name} and re-owned ${path} to it.`,
    username: name,
  };
}

export function registerServiceUser(server: McpServer) {
  server.registerTool(
    "serviceuser.create",
    {
      description:
        "Creates a dedicated, unprivileged Unix service account for an app and re-owns its project directory " +
        "to that account — the DAC (Discretionary Access Control) layer of DeployGuard's secure deployment " +
        "flow, independent of AppArmor. Call this when the user wants to deploy an app securely and needs it " +
        "to run as its own isolated user rather than root or a shared account. Safe to call again on a redeploy " +
        "— reuses the existing account instead of erroring if it already exists.",
      inputSchema: {
        path: z.string(),
        name: z.string(),
        confirm: z.literal(true),
      },
      outputSchema: {
        ...checkResultShape,
        username: z.string(),
      },
    },
    async ({ path, name }) => {
      const result = await createServiceUser(path, name);
      return {
        content: [{ type: "text" as const, text: result.summary }],
        structuredContent: result,
      };
    }
  );
}
