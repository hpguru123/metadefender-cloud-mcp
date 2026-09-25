#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { MetaDefenderClient } from "./client.js";
import { summarizeApiUsage, summarizeReputation, summarizeScan } from "./summarize.js";

const apiKey = process.env.METADEFENDER_API_KEY;
if (!apiKey) {
  console.error("METADEFENDER_API_KEY is not set. Get a key at https://metadefender.opswat.com/account");
  process.exit(1);
}

const client = new MetaDefenderClient({ apiKey, baseUrl: process.env.METADEFENDER_BASE_URL });
const server = new McpServer({ name: "metadefender-cloud", version: "0.1.1" });

const rawFlag = z.boolean().optional().describe("Return the full API response instead of a summary");

function ok(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

// Wrap each handler so API errors come back as tool errors the model can read and act on.
function tool<A>(fn: (args: A) => Promise<unknown>) {
  return async (args: A) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      return { isError: true, content: [{ type: "text" as const, text: (e as Error).message }] };
    }
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function pollScan(dataId: string, timeoutSec: number) {
  const deadline = Date.now() + timeoutSec * 1000;
  let result = await client.getScanResult(dataId);
  while (result?.scan_results?.progress_percentage !== 100 && Date.now() < deadline) {
    await sleep(3000);
    result = await client.getScanResult(dataId);
  }
  return result;
}

server.registerTool(
  "lookup_hash",
  {
    title: "Look up file hash",
    description:
      "Check a file's MD5, SHA1 or SHA256 against MetaDefender Cloud's multiscanning results. " +
      "Costs one prevention API call. Returns 404 if the hash has never been seen.",
    inputSchema: { hash: z.string().regex(/^[A-Fa-f0-9]{32,64}$/).describe("MD5, SHA1 or SHA256"), raw: rawFlag },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async ({ hash, raw }: { hash: string; raw?: boolean }) => {
    const r = await client.lookupHash(hash);
    return raw ? r : summarizeScan(r);
  }),
);

server.registerTool(
  "lookup_hashes_bulk",
  {
    title: "Look up many file hashes",
    description: "Check up to 1000 hashes in one request. Costs one prevention API call per hash.",
    inputSchema: { hashes: z.array(z.string()).min(1).max(1000) },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async ({ hashes }: { hashes: string[] }) => {
    const r = await client.lookupHashes(hashes);
    const rows: any[] = Array.isArray(r) ? r : (r?.data ?? []);
    return rows.map((x) => ({
      hash: x.hash,
      verdict: x.scan_result_i === undefined ? x.error ?? "not found" : x.scan_all_result_a ?? x.scan_result_i,
      detected_by: x.total_detected_avs,
      threat_name: x.threat_name,
    }));
  }),
);

server.registerTool(
  "scan_file",
  {
    title: "Scan a local file",
    description:
      "Upload a file from the local filesystem to MetaDefender Cloud for multiscanning. " +
      "Optionally add Deep CDR sanitization, archive extraction or sandbox analysis via `rule`. " +
      "Waits for the result up to `wait_seconds`; if still running, returns data_id for get_scan_result. " +
      "Uploads are shared with OPSWAT unless private_scan is true (requires a paid key).",
    inputSchema: {
      path: z.string().describe("Absolute path to the file to upload"),
      rule: z
        .string()
        .optional()
        .describe("Comma-separated workflow rules, e.g. 'multiscan', 'multiscan,sanitize', 'multiscan,sandbox', 'unarchive'"),
      archive_password: z.string().optional().describe("Password for an encrypted archive"),
      private_scan: z.boolean().optional().describe("Do not share the file or its results (paid keys only)"),
      wait_seconds: z.number().int().min(0).max(300).optional().describe("How long to wait for results (default 60)"),
      raw: rawFlag,
    },
    annotations: { readOnlyHint: false, openWorldHint: true },
  },
  tool(async (a: { path: string; rule?: string; archive_password?: string; private_scan?: boolean; wait_seconds?: number; raw?: boolean }) => {
    const up = await client.uploadFile(a.path, { rule: a.rule, password: a.archive_password, privateScan: a.private_scan });
    const dataId: string = up.data_id;
    const r = await pollScan(dataId, a.wait_seconds ?? 60);
    const out = a.raw ? r : summarizeScan(r);
    return { ...(out as object), data_id: dataId, sandbox_id: up.sandbox_id ?? (out as any).sandbox_id };
  }),
);

server.registerTool(
  "get_scan_result",
  {
    title: "Get file scan result",
    description: "Fetch the current result for a file upload by its data_id. Check progress_percentage for completion.",
    inputSchema: { data_id: z.string(), raw: rawFlag },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async ({ data_id, raw }: { data_id: string; raw?: boolean }) => {
    const r = await client.getScanResult(data_id);
    return raw ? r : summarizeScan(r);
  }),
);

server.registerTool(
  "get_sanitized_file",
  {
    title: "Get Deep CDR sanitized file link",
    description: "Get the download link for the sanitized (Deep CDR) version of a file scanned with rule 'sanitize'.",
    inputSchema: { data_id: z.string() },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async ({ data_id }: { data_id: string }) => client.getSanitizedFile(data_id)),
);

server.registerTool(
  "get_sandbox_report",
  {
    title: "Get sandbox report",
    description:
      "Fetch dynamic analysis (sandbox) results, either by sandbox_id from a scan with rule 'sandbox', or by file hash.",
    inputSchema: {
      sandbox_id: z.string().optional(),
      hash: z.string().optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async ({ sandbox_id, hash }: { sandbox_id?: string; hash?: string }) => {
    if (sandbox_id) return client.getSandboxReport(sandbox_id);
    if (hash) return client.getHashSandbox(hash);
    throw new Error("Provide sandbox_id or hash");
  }),
);

for (const [name, title, field, fn] of [
  ["lookup_ip", "Look up IP reputation", "ip", (v: string) => client.lookupIp(v)],
  ["lookup_domain", "Look up domain reputation", "domain", (v: string) => client.lookupDomain(v)],
  ["lookup_url", "Look up URL reputation", "url", (v: string) => client.lookupUrl(v)],
] as const) {
  server.registerTool(
    name,
    {
      title,
      description: `${title} across MetaDefender Cloud's threat intelligence sources. Costs one reputation API call.`,
      inputSchema: { [field]: z.string().min(1), raw: rawFlag },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    tool(async (args: Record<string, any>) => {
      const r = await fn(args[field]);
      return args.raw ? r : summarizeReputation(r);
    }),
  );
}

server.registerTool(
  "lookup_cve",
  {
    title: "Look up CVE",
    description: "Get details for a CVE (e.g. CVE-2021-44228), including severity and affected products.",
    inputSchema: { cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/i) },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async ({ cve }: { cve: string }) => client.lookupCve(cve.toUpperCase())),
);

server.registerTool(
  "get_api_usage",
  {
    title: "Get API key usage and limits",
    description: "Show the API key's plan details and daily limits for each API type.",
    inputSchema: {},
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  tool(async () => {
    const [info, limits] = await Promise.all([client.getApiKeyInfo(), client.getApiKeyLimits()]);
    return summarizeApiUsage(info, limits);
  }),
);

await server.connect(new StdioServerTransport());
