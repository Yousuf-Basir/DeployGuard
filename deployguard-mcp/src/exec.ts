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
