# Solarium JSON-RPC / MCP-style server

Solarium can run as a newline-delimited stdio JSON-RPC 2.0 server for external agents and MCP-style clients.

Start the server:

```bash
npm run dev -- server
# or, after build:
node dist/cli/index.js server
```

Each request is one JSON object per line. Each response is one JSON object per line. The server supports basic MCP-style methods:

- `initialize`
- `ping`
- `tools/list`
- `tools/call`

It also supports direct JSON-RPC calls where the method is a Solarium tool name, such as `solarium.browse`.

## Initialize

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"solarium","version":"0.1.0"},"capabilities":{"tools":{}}}}
```

## List tools

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

## Call a tool MCP-style

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"solarium.browse","arguments":{"url":"https://example.com","observe":true,"headless":true}}}
```

`tools/call` returns both MCP-style text content and `structuredContent` containing the raw Solarium result.

## Call a tool directly

```json
{"jsonrpc":"2.0","id":4,"method":"solarium.scopeCheck","params":{"url":"https://example.com","scope":{"allowedHosts":["example.com"],"authorizationNote":"Authorized example"}}}
```

## Available tools

- `solarium.browse` — open a URL; optionally observe, extract text, or screenshot.
- `solarium.inspect` — inspect a page and return selector/action candidates.
- `solarium.plan` — generate conservative session actions from an inspect result.
- `solarium.session` — run an `AgentAction[]` browser session.
- `solarium.loop` — run a bounded inspect-plan-act loop.
- `solarium.crawl` — crawl in-scope pages; requires a scope policy.
- `solarium.audit` — passive defensive audit of an authorized page.
- `solarium.scopeCheck` — check a URL against a scope policy.
- `solarium.validate` — validate job/scope/actions JSON.
- `solarium.profiles` — list built-in browser profiles.
- `solarium.profile` — show a built-in browser profile.
- `solarium.replay` — summarize a JSONL event timeline from disk.
- `solarium.manifest` — create a SHA-256 artifact manifest.

## Security boundary

External agents should pass explicit `scope` objects for security-sensitive browsing, crawling, auditing, and loop runs. `solarium.crawl` requires scope. Storage state files, downloads, screenshots, and traces can contain sensitive local artifacts; keep generated paths under an agent-controlled evidence directory and out of source control.

The server uses stdio only. It does not open a network listener.


## TypeScript client / Vegvisir adapter

For launching and supervising this server from Vegvisir or another TypeScript agent harness, see `docs/vegvisir-adapter.md`.
