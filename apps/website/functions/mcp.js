import { createPublicMcpEndpoint } from "../server/mcp-service.mjs";

const handle = createPublicMcpEndpoint();
export const onRequest = (context) => handle(context);
