import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerCheckDependencies } from "./deps.js";

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

registerCheckDependencies(server);

await server.connect(new StdioServerTransport());
