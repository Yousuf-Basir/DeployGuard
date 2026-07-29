import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { runChecked } from "./exec.js";
import { checkResultShape } from "./schema.js";
import { unitName } from "./systemd.js";

export interface DeployUpdateResult {
  status: "ok" | "warn" | "fail";
  summary: string;
  output: string;
  [key: string]: unknown;
}

// The real owner is the source of truth, not a guessed naming convention —
// serviceuser.create (Stage 7) may have re-owned the directory to an
// account whose name doesn't exactly match `name`, and trusting a mismatch
// here would pull/build as the wrong user, silently breaking the DAC
// isolation Stage 7 set up.
async function getOwner(path: string): Promise<string | null> {
  const { code, stdout } = await runChecked("stat", ["-c", "%U", path]);
  if (code !== 0) return null;
  const owner = stdout.trim();
  return owner || null;
}

// Stage 9: the ongoing half of the deployment flow — pulling and rebuilding
// an app Stage 7/8 already deployed, without breaking the DAC boundary that
// deployment set up. Pull/build runs as the project's actual owning
// account via `runuser`, never as root or whichever account is running
// this MCP server — files pulled under the wrong owner would silently
// defeat serviceuser.create's isolation on the very next redeploy.
export async function deployUpdate(name: string, path: string, buildCommand?: string): Promise<DeployUpdateResult> {
  const owner = await getOwner(path);
  if (!owner) {
    return {
      status: "fail",
      summary: `FAIL: could not determine the owner of "${path}" — does it exist?`,
      output: "",
    };
  }

  const script = `cd ${path} && git pull${buildCommand ? ` && ${buildCommand}` : ""}`;
  const pull = await runChecked("runuser", ["-u", owner, "--", "bash", "-c", script]);
  const pullOutput = [pull.stdout, pull.stderr].filter(Boolean).join("\n");

  if (pull.code !== 0) {
    return {
      status: "fail",
      summary: `FAIL: pull/build failed as "${owner}" — the running service was left untouched. See output.`,
      output: pullOutput,
    };
  }

  const unit = unitName(name);
  const restart = await runChecked("systemctl", ["restart", unit]);
  if (restart.code !== 0) {
    return {
      status: "fail",
      summary:
        `FAIL: pulled and built successfully as "${owner}", but systemctl restart ${unit} failed — the app ` +
        `may still be running the old build. Error: ${restart.stderr.trim() || "unknown error"}`,
      output: pullOutput,
    };
  }

  return {
    status: "ok",
    summary: `OK: pulled and built as "${owner}", ${unit}.service restarted.`,
    output: pullOutput,
  };
}

export function registerDeploy(server: McpServer) {
  server.registerTool(
    "deploy.update",
    {
      description:
        "Pulls the latest commit and rebuilds an app DeployGuard already deployed, then restarts its systemd " +
        "service. Call this when the user asks to redeploy, deploy the latest update/changes, or pull and " +
        "restart an app that's already running under DeployGuard. Runs the pull/build as the project " +
        "directory's actual owning account (via runuser) — never as root or whichever account is running this " +
        "MCP server — so the DAC isolation serviceuser.create set up isn't broken by files landing under the " +
        "wrong owner. If the pull or build fails, the running service is left untouched rather than restarted " +
        "into a broken state.",
      inputSchema: {
        name: z.string(),
        path: z.string(),
        buildCommand: z.string().optional(),
        confirm: z.literal(true),
      },
      outputSchema: {
        ...checkResultShape,
        output: z.string(),
      },
    },
    async ({ name, path, buildCommand }) => {
      const result = await deployUpdate(name, path, buildCommand);
      return {
        content: [{ type: "text" as const, text: `${result.summary}\n\n${result.output}`.trim() }],
        structuredContent: result,
      };
    }
  );
}
