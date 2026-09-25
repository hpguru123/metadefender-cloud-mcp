// End-to-end: runs the built server over stdio against a local mock of the MetaDefender API.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const seen = [];
let polls = 0;
const scan = (progress) => ({
  data_id: "d1",
  file_info: { display_name: "eicar.com", sha256: "abc" },
  scan_results: {
    scan_all_result_a: progress === 100 ? "Infected" : "In Progress",
    progress_percentage: progress,
    total_detected_avs: 1,
    total_avs: 2,
    scan_details: { EngA: { threat_found: "EICAR-Test-File" }, EngB: { threat_found: "" } },
  },
});
const mock = http.createServer((req, res) => {
  let body = [];
  req.on("data", (c) => body.push(c));
  req.on("end", () => {
    seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(body).toString() });
    const send = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (req.headers.apikey !== "test-key") return send(401, { error: { messages: ["Invalid apikey"] } });
    const u = req.url;
    if (u === "/v4/hash/44d88612fea8a8f36de82e1278abb02f") return send(200, scan(100));
    if (u === "/v4/hash/00000000000000000000000000000000") return send(404, { error: { messages: ["The hash was not found"] } });
    if (u === "/v4/file" && req.method === "POST") return send(200, { data_id: "d1" });
    if (u === "/v4/file/d1") return send(200, scan(++polls >= 2 ? 100 : 50));
    if (u === "/v4/ip/1.2.3.4") return send(200, { address: "1.2.3.4", lookup_results: { detected_by: 1, sources: [
      { provider: "webroot", assessment: "Phishing" }, { provider: "x", assessment: "trustworthy" }] } });
    if (u === "/v4/url/" + encodeURIComponent("http://evil.test/a?b=c")) return send(200, { address: "http://evil.test/a?b=c", lookup_results: { detected_by: 0, sources: [] } });
    if (u === "/v4/apikey/") return send(200, {
      apikey: "test-key", portal_api_key: "portal-secret", user_id: "u-123", account_id: "acc-9", nickname: "derek",
      email: "d@example.com", paid_user: 0, limit_interval: "daily", limit_reputation: 1000, max_upload_file_size: 140,
      limit_extra: { nested: "portal-secret" }, some_future_field: "leaky" });
    if (u === "/v4/apikey/limits/status") return send(200, { limit_prevention: 1000, reset_in: "5h", user_id: "u-123" });
    send(404, { error: { messages: ["no route " + u] } });
  });
});

let client;
before(async () => {
  await new Promise((r) => mock.listen(0, r));
  client = new Client({ name: "test", version: "0" });
  await client.connect(new StdioClientTransport({
    command: "node", args: [process.env.SERVER_ENTRY ?? "dist/index.js"],
    env: { ...process.env, METADEFENDER_API_KEY: "test-key", METADEFENDER_BASE_URL: `http://127.0.0.1:${mock.address().port}/v4` },
  }));
});
after(async () => { await client?.close(); mock.close(); });

const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError, text: r.content[0].text, json: r.isError ? null : JSON.parse(r.content[0].text) };
};

test("lists all tools", async () => {
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), [
    "get_api_usage", "get_sandbox_report", "get_sanitized_file", "get_scan_result", "lookup_cve", "lookup_domain",
    "lookup_hash", "lookup_hashes_bulk", "lookup_ip", "lookup_url", "scan_file",
  ]);
});

test("hash lookup summarizes detections", async () => {
  const r = await call("lookup_hash", { hash: "44d88612fea8a8f36de82e1278abb02f" });
  assert.equal(r.json.verdict, "Infected");
  assert.deepEqual(r.json.detections, [{ engine: "EngA", threat: "EICAR-Test-File" }]);
});

test("unknown hash is a readable tool error", async () => {
  const r = await call("lookup_hash", { hash: "00000000000000000000000000000000" });
  assert.equal(r.isError, true);
  assert.match(r.text, /404.*not found/);
});

test("scan_file uploads with headers and polls to completion", async () => {
  const dir = mkdtempSync(join(tmpdir(), "md-"));
  const f = join(dir, "sample.txt");
  writeFileSync(f, "hello");
  const r = await call("scan_file", { path: f, rule: "multiscan,sanitize", wait_seconds: 10 });
  const up = seen.find((s) => s.url === "/v4/file");
  assert.equal(up.headers.filename, "sample.txt");
  assert.equal(up.headers.rule, "multiscan,sanitize");
  assert.equal(up.body, "hello");
  assert.equal(r.json.data_id, "d1");
  assert.equal(r.json.progress_percentage, 100);
});

test("ip reputation keeps only flagged sources", async () => {
  const r = await call("lookup_ip", { ip: "1.2.3.4" });
  assert.equal(r.json.flagged_sources.length, 1);
  assert.equal(r.json.total_sources, 2);
});

test("url is path-encoded", async () => {
  const r = await call("lookup_url", { url: "http://evil.test/a?b=c" });
  assert.equal(r.isError, undefined);
});

test("api usage returns only allowlisted plan and limit fields", async () => {
  const r = await call("get_api_usage");
  for (const secret of ["test-key", "portal-secret", "u-123", "acc-9", "derek", "d@example.com", "leaky"]) {
    assert.equal(r.text.includes(secret), false, `leaked ${secret}`);
  }
  assert.deepEqual(r.json.plan, { paid_user: 0, limit_interval: "daily", limit_reputation: 1000, max_upload_file_size: 140 });
  assert.deepEqual(r.json.limits, { limit_prevention: 1000, reset_in: "5h" });
});
