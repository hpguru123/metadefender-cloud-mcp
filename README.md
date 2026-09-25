# MetaDefender Cloud MCP server

An MCP server that lets Claude use the [OPSWAT MetaDefender Cloud](https://metadefender.opswat.com) v4 API: hash lookups, file multiscanning with Deep CDR and sandbox, and IP, domain, URL and CVE reputation.

## Tools

| Tool | What it does | API |
|---|---|---|
| `lookup_hash` | Multiscan verdict for an MD5/SHA1/SHA256 | `GET /hash/{hash}` |
| `lookup_hashes_bulk` | Up to 1000 hashes at once | `POST /hash` |
| `scan_file` | Upload a local file, optionally with `sanitize`, `sandbox` or `unarchive` rules, and wait for the result | `POST /file`, `GET /file/{data_id}` |
| `get_scan_result` | Poll a scan by `data_id` | `GET /file/{data_id}` |
| `get_sanitized_file` | Download link for the Deep CDR output | `GET /file/converted/{data_id}` |
| `get_sandbox_report` | Dynamic analysis by `sandbox_id` or hash | `GET /sandbox/{id}`, `GET /hash/{hash}/sandbox` |
| `lookup_ip` / `lookup_domain` / `lookup_url` | Reputation across threat intel sources | `GET /ip/…`, `/domain/…`, `/url/…` |
| `lookup_cve` | CVE details | `GET /cve/{id}` |
| `get_api_usage` | Plan and remaining daily limits | `GET /apikey/`, `/apikey/limits/status` |

Results are summarized by default (verdict, detecting engines, flagged sources) to keep Claude's context small. Pass `raw: true` for the full API response.

## Setup

```bash
npm install
npm run build
```

Get an API key from https://metadefender.opswat.com/account and add the server to Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "metadefender": {
      "command": "node",
      "args": ["/absolute/path/to/metadefender-mcp/dist/index.js"],
      "env": { "METADEFENDER_API_KEY": "your-key" }
    }
  }
}
```

Or with Claude Code:

```bash
claude mcp add metadefender -e METADEFENDER_API_KEY=your-key -- node /absolute/path/to/dist/index.js
```

## Notes

- Files uploaded with `scan_file` are shared with OPSWAT unless `private_scan: true` (paid plans only).
- Each call consumes credits from the matching daily limit (prevention, reputation, sandbox, CDR). `get_api_usage` shows what's left.
- The key is only read from `METADEFENDER_API_KEY` and is never returned in tool output.

## Tests

`npm test` builds the server and runs it over stdio against a local mock of the API.
