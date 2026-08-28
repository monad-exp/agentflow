import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

import { PrismaClient } from "@prisma/client";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import {
  addHunts,
  addHuntsInput,
  addLead,
  addLeadInput,
  BugDbScope,
  createFindings,
  createFindingsInput,
  finishHunt,
  finishHuntInput,
  getFinding,
  getFindingInput,
  getHunt,
  getHuntInput,
  listHuntsAndLeads,
  listHuntsAndLeadsInput,
  setRereview,
  setReviewInput,
  setTriage,
} from "./bugdb.js";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
const runId = requiredEnv("AGENTFLOW_RUN_ID");
const contextSecret = requiredEnv("AGENTFLOW_CONTEXT_SECRET");
const controlToken = requiredEnv("AGENTFLOW_CONTROL_TOKEN");
const connectorNonce = requiredEnv("AGENTFLOW_CONNECTOR_NONCE");

const prisma = new PrismaClient();

type ToolDefinition = {
  description: string;
  inputSchema: z.ZodObject<z.ZodRawShape>;
  readOnly?: boolean;
  run: (scope: BugDbScope, input: never) => Promise<unknown>;
};

const tools: Record<string, ToolDefinition> = {
  add_hunts: {
    description: "Insert selected FILE, THREAT_MODEL, or ROAM Hunts into the injected AgentFlow run.",
    inputSchema: addHuntsInput,
    run: (scope, input) => addHunts(prisma, scope, input),
  },
  get_hunt: {
    description: "Read the Hunt injected into this hunter, including any durable Leads.",
    inputSchema: getHuntInput,
    readOnly: true,
    run: (scope) => getHunt(prisma, scope),
  },
  add_lead: {
    description: "Append one immutable Lead to the injected Hunt using a stable caller key.",
    inputSchema: addLeadInput,
    run: (scope, input) => addLead(prisma, scope, input),
  },
  finish_hunt: {
    description: "Set the injected Hunt result once to BUG_FOUND, EXHAUSTED, or BLOCKED.",
    inputSchema: finishHuntInput,
    run: (scope, input) => finishHunt(prisma, scope, input),
  },
  list_hunts_and_leads: {
    description: "Read every Hunt and immutable Lead in the injected AgentFlow run.",
    inputSchema: listHuntsAndLeadsInput,
    readOnly: true,
    run: (scope) => listHuntsAndLeads(prisma, scope),
  },
  create_findings: {
    description: "Create or verify canonical Findings and partition all currently unassigned same-run Leads transactionally.",
    inputSchema: createFindingsInput,
    run: (scope, input) => createFindings(prisma, scope, input),
  },
  get_finding: {
    description: "Read the Finding injected into this reviewer or reporter with all source Leads.",
    inputSchema: getFindingInput,
    readOnly: true,
    run: (scope) => getFinding(prisma, scope),
  },
  set_triage: {
    description: "Set the injected Finding's triage verdict and assessment once, atomically.",
    inputSchema: setReviewInput,
    run: (scope, input) => setTriage(prisma, scope, input),
  },
  set_rereview: {
    description: "Set the injected Finding's independent re-review once, atomically.",
    inputSchema: setReviewInput,
    run: (scope, input) => setRereview(prisma, scope, input),
  },
};

type ToolName = keyof typeof tools;
type Headers = Record<string, string | string[] | undefined>;

function header(headers: Headers, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function safeTokenEqual(actual: string | undefined, expected: string): boolean {
  if (!actual) return false;
  const left = Buffer.from(actual, "utf8");
  const right = Buffer.from(expected, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

function scopeFromHeaders(headers: Headers): BugDbScope {
  const requestRunId = header(headers, "x-agentflow-run-id");
  const runSignature = header(headers, "x-agentflow-run-signature");
  const expectedRunSignature = createHmac("sha256", contextSecret).update(runId).digest("hex");
  if (requestRunId !== runId || !safeTokenEqual(runSignature, expectedRunSignature)) {
    throw new Error("invalid AgentFlow run scope");
  }
  const itemId = header(headers, "x-agentflow-item-id");
  const signature = header(headers, "x-agentflow-item-signature");
  if (itemId === undefined && signature === undefined) return { runId };
  if (!itemId || !signature || !/^[0-9a-f]{64}$/.test(signature)) {
    throw new Error("invalid AgentFlow item scope");
  }
  const expected = createHmac("sha256", contextSecret)
    .update(runId)
    .update("\0")
    .update(itemId)
    .digest("hex");
  if (!safeTokenEqual(signature, expected)) throw new Error("invalid AgentFlow item scope signature");
  return { runId, itemId };
}

function toolScopeFromHeaders(headers: Headers): Set<ToolName> {
  if (safeTokenEqual(header(headers, "x-agentflow-control-token"), controlToken)) {
    return new Set(Object.keys(tools) as ToolName[]);
  }
  const scope = header(headers, "x-agentflow-tool-scope");
  const signature = header(headers, "x-agentflow-tool-signature");
  if (scope === undefined || !signature) throw new Error("missing AgentFlow tool scope");
  const expected = createHmac("sha256", contextSecret)
    .update(runId)
    .update("\0tools\0")
    .update(scope)
    .digest("hex");
  if (!safeTokenEqual(signature, expected)) throw new Error("invalid AgentFlow tool scope");
  const names = scope === "" ? [] : scope.split(",");
  if (names.some((name) => !(name in tools))) throw new Error("unknown AgentFlow tool scope");
  return new Set(names as ToolName[]);
}

function toolResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }] };
}

async function callTool(name: string, raw: unknown, headers: Headers) {
  const tool = tools[name as ToolName];
  if (!tool) throw new Error(`unknown tool ${name}`);
  if (!toolScopeFromHeaders(headers).has(name as ToolName)) {
    throw new Error(`tool ${name} is not allowed in this node`);
  }
  const input = tool.inputSchema.parse(raw);
  return tool.run(scopeFromHeaders(headers), input as never);
}

function buildMcpServer(allowedTools: Set<ToolName>) {
  const server = new McpServer({ name: "agentflow-bugdb", version: "0.1.0" });
  for (const [name, tool] of Object.entries(tools)) {
    if (!allowedTools.has(name as ToolName)) continue;
    server.registerTool(
      name,
      {
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: {
          readOnlyHint: tool.readOnly ?? false,
          destructiveHint: false,
          idempotentHint: true,
        },
      },
      async (input: unknown, extra: any) => toolResult(
        await tool.run(
          scopeFromHeaders((extra.requestInfo?.headers ?? {}) as Headers),
          input as never,
        ),
      ),
    );
  }
  return server;
}

const host = process.env.BUGDB_HOST ?? "127.0.0.1";
const port = Number.parseInt(process.env.BUGDB_PORT ?? "4312", 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("BUGDB_PORT must be an integer from 1 through 65535");
}

const app = createMcpExpressApp({ host });

app.use("/mcp", (request, response, next) => {
  try {
    scopeFromHeaders(request.headers as Headers);
    next();
  } catch {
    response.status(403).json({ error: "invalid AgentFlow run scope" });
  }
});

type McpSession = { server: McpServer; transport: StreamableHTTPServerTransport };
const sessions = new Map<string, McpSession>();

function sessionId(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

app.post("/mcp", async (request, response) => {
  try {
    const id = sessionId(request.headers["mcp-session-id"]);
    let session = id ? sessions.get(id) : undefined;
    if (!session && !id && isInitializeRequest(request.body)) {
      const server = buildMcpServer(toolScopeFromHeaders(request.headers as Headers));
      let createdSession!: McpSession;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        enableJsonResponse: true,
        onsessioninitialized: (initializedId) => {
          sessions.set(initializedId, createdSession);
        },
        onsessionclosed: (closedId) => {
          sessions.delete(closedId);
        },
      });
      createdSession = { server, transport };
      session = createdSession;
      transport.onerror = (error) => {
        process.stderr.write(`MCP transport error: ${error.stack ?? error.message}\n`);
      };
      transport.onclose = () => {
        const closedId = transport.sessionId;
        if (closedId) sessions.delete(closedId);
      };
      await server.connect(transport);
    }
    if (!session) {
      response.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID provided" },
        id: null,
      });
      return;
    }
    await session.transport.handleRequest(request, response, request.body);
  } catch (error) {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    process.stderr.write(`MCP request failed: ${message}\n`);
    if (!response.headersSent) {
      response.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

app.all("/mcp", async (request, response) => {
  const id = sessionId(request.headers["mcp-session-id"]);
  const session = id ? sessions.get(id) : undefined;
  if (!session) {
    response.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Bad Request: No valid session ID provided" },
      id: null,
    });
    return;
  }
  await session.transport.handleRequest(request, response);
});

// Pi invokes this narrow bridge; it reaches the exact same schemas and handlers.
app.post("/tools/call", async (request, response) => {
  try {
    const body = z.object({ name: z.string(), arguments: z.unknown() }).parse(request.body);
    response.json({ result: await callTool(body.name, body.arguments, request.headers as Headers) });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    response.status(400).json({ error: message });
  }
});

app.get("/orchestration/:resource", async (request, response) => {
  if (!safeTokenEqual(header(request.headers as Headers, "x-agentflow-control-token"), controlToken)) {
    response.status(403).json({ error: "invalid AgentFlow control token" });
    return;
  }
  if (request.params.resource === "hunts") {
    const hunts = await prisma.hunt.findMany({
      where: { runId },
      select: { id: true },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    });
    response.json(hunts.map((hunt) => hunt.id));
    return;
  }
  if (request.params.resource === "findings") {
    const findings = await prisma.finding.findMany({
      where: { runId },
      select: { id: true },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    });
    response.json(findings.map((finding) => finding.id));
    return;
  }
  response.status(404).json({ error: "unknown orchestration resource" });
});

app.get("/healthz", (request, response) => {
  if (!safeTokenEqual(header(request.headers as Headers, "x-agentflow-control-token"), controlToken)) {
    response.status(403).json({ error: "invalid AgentFlow control token" });
    return;
  }
  response.json({ ok: true, runId, nonce: connectorNonce });
});

const httpServer = app.listen(port, host, () => {
  process.stdout.write(`BugDB connector listening on http://${host}:${port}/mcp for run ${runId}\n`);
});

async function shutdown(signal: string) {
  process.stdout.write(`BugDB connector stopping on ${signal}\n`);
  httpServer.close();
  await Promise.all([...sessions.values()].map((session) => session.server.close()));
  sessions.clear();
  await prisma.$disconnect();
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
