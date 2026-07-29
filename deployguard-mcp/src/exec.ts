import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function run(command: string, args: string[] = []): Promise<string> {
  try {
    const { stdout } = await execFileAsync(command, args);
    return stdout;
  } catch (err: any) {
    return err.stdout ?? "";
  }
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

// Unlike run(), surfaces exit code and stderr instead of swallowing them —
// needed by tools that must distinguish a real failure (e.g. apparmor_parser
// rejecting a malformed profile) from an empty/absent result.
export async function runChecked(command: string, args: string[] = []): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args);
    return { stdout, stderr, code: 0 };
  } catch (err: any) {
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? String(err.message ?? err),
      code: typeof err.code === "number" ? err.code : 1,
    };
  }
}
