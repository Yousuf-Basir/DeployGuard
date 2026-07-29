import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerCheckDependencies } from "./deps.js";
import { registerFirewall } from "./firewall.js";
import { registerFail2ban } from "./fail2ban.js";
import { registerApt } from "./apt.js";
import { registerApparmor } from "./apparmor.js";
import { registerServiceUser } from "./serviceuser.js";
import { registerSystemd } from "./systemd.js";
import { registerDeploy } from "./deploy.js";
import { registerApps } from "./apps.js";
import { registerReport } from "./report.js";

const server = new McpServer(
  { name: "deployguard", version: "0.1.0" },
  {
    instructions:
      "DeployGuard checks and hardens security on this host (firewall, fail2ban, AppArmor, APT sources), and " +
      "owns securely deploying and managing apps here (dedicated service account + AppArmor confinement + " +
      "systemd, replacing PM2 or manual process management for anything it deploys). For any question about " +
      "this server's security status, readiness, or hardening, prefer calling these tools over reading source " +
      "files or reasoning from general knowledge. For a general 'is this server secure' question, call " +
      "security.full_report rather than each individual check. Call system.check_dependencies first if unsure " +
      "whether the required CLI tools are installed. For deploying, redeploying, or managing an app (list, " +
      "stop, restart, remove, adjust limits, view logs), prefer serviceuser.create/apparmor.*/systemd.*/" +
      "deploy.update/apps.* over reconstructing the same actions with raw shell commands.",
  }
);

registerCheckDependencies(server);
registerFirewall(server);
registerFail2ban(server);
registerApt(server);
registerApparmor(server);
registerServiceUser(server);
registerSystemd(server);
registerDeploy(server);
registerApps(server);
registerReport(server);

await server.connect(new StdioServerTransport());
