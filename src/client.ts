import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";

export class MetaDefenderError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

export interface ClientOptions {
  apiKey: string;
  baseUrl?: string;
}

// Cloud accepts files up to 140 MB on paid plans; smaller on free keys. Let the API decide,
// but refuse anything absurd so we don't read huge files into memory.
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;

export class MetaDefenderClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(opts: ClientOptions) {
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl ?? "https://api.metadefender.com/v4").replace(/\/+$/, "");
  }

  private async request(path: string, init: RequestInit = {}): Promise<any> {
    const headers = new Headers(init.headers);
    headers.set("apikey", this.apiKey);
    const res = await fetch(`${this.baseUrl}${path}`, { ...init, headers });
    const text = await res.text();
    let body: any;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { raw: text };
    }
    if (!res.ok) {
      const msg = body?.error?.messages?.join("; ") ?? body?.error?.message ?? text ?? res.statusText;
      throw new MetaDefenderError(`MetaDefender API ${res.status} on ${path}: ${msg}`, res.status);
    }
    return body;
  }

  private json(path: string, payload: unknown) {
    return this.request(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  lookupHash(hash: string) {
    return this.request(`/hash/${encodeURIComponent(hash)}`);
  }

  lookupHashes(hashes: string[]) {
    return this.json("/hash", { hash: hashes });
  }

  lookupIp(ip: string) {
    return this.request(`/ip/${encodeURIComponent(ip)}`);
  }

  lookupDomain(domain: string) {
    return this.request(`/domain/${encodeURIComponent(domain)}`);
  }

  lookupUrl(url: string) {
    return this.request(`/url/${encodeURIComponent(url)}`);
  }

  lookupCve(cve: string) {
    return this.request(`/cve/${encodeURIComponent(cve)}`);
  }

  async uploadFile(
    filePath: string,
    opts: { rule?: string; password?: string; privateScan?: boolean; filename?: string } = {},
  ) {
    const info = await stat(filePath);
    if (!info.isFile()) throw new MetaDefenderError(`${filePath} is not a file`);
    if (info.size > MAX_UPLOAD_BYTES) {
      throw new MetaDefenderError(`${filePath} is ${info.size} bytes, over the ${MAX_UPLOAD_BYTES} byte limit`);
    }
    const data = await readFile(filePath);
    const headers: Record<string, string> = {
      "content-type": "application/octet-stream",
      filename: opts.filename ?? basename(filePath),
    };
    if (opts.rule) headers.rule = opts.rule;
    if (opts.password) headers.password = opts.password;
    if (opts.privateScan) headers.privateprocessing = "1";
    return this.request("/file", { method: "POST", headers, body: data });
  }

  getScanResult(dataId: string) {
    return this.request(`/file/${encodeURIComponent(dataId)}`);
  }

  getSanitizedFile(dataId: string) {
    return this.request(`/file/converted/${encodeURIComponent(dataId)}`);
  }

  getSandboxReport(sandboxId: string) {
    return this.request(`/sandbox/${encodeURIComponent(sandboxId)}`);
  }

  getHashSandbox(hash: string) {
    return this.request(`/hash/${encodeURIComponent(hash)}/sandbox`);
  }

  getApiKeyInfo() {
    return this.request("/apikey/");
  }

  getApiKeyLimits() {
    return this.request("/apikey/limits/status");
  }
}
