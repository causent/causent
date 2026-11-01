# Runtime architecture

This page documents Causent internals that are useful to contributors and
integrators but are not part of the main onboarding path.

## Persistence

Causent can persist investigations, lifecycle events, evidence, hypotheses,
experiments, patches, and verification reports in SQLite. The store is used by
the gateway and MCP server when they need durable investigation state.

Persistence does not make a diagnosis correct. It records what was observed so
that the result can be inspected and recovered.

## Gateway

The gateway is a small OpenAI-compatible HTTP adapter. It keeps provider-specific
wire formats outside the diagnosis engine and can use Ollama, OpenAI-compatible
providers, Gemini, or another configured upstream supported by the repository.

Start it locally with:

```sh
CAUSENT_GATEWAY_PROVIDER=ollama \
CAUSENT_GATEWAY_MODEL=qwen2.5:7b \
go run ./cmd/gateway
```

Endpoints:

- `GET /health`
- `GET /v1/models`
- `POST /v1/chat/completions`
- `GET /v1/investigations/<id>/events`

The gateway currently handles non-streaming model completions. Request and
output limits are enforced by the gateway and provider clients.

## Server-Sent Events

`GET /v1/investigations/<id>/events` streams persisted investigation lifecycle
events as Server-Sent Events.

The stream:

- sends the existing events after the supplied cursor;
- accepts `Last-Event-ID` for reconnecting;
- polls for newly persisted events;
- sends keepalive comments every 15 seconds;
- closes when the client context ends.

If the gateway was started without a SQLite store, model requests still work,
but the SSE endpoint returns that investigation streaming is unavailable.

Example:

```sh
curl -N \
  -H 'Accept: text/event-stream' \
  http://127.0.0.1:8787/v1/investigations/INVESTIGATION_ID/events
```

## MCP server

The MCP server is a separate local integration for agent clients. It uses stdio
JSON-RPC and requires an explicitly authorized repository root.

```sh
go build -o causent-mcp ./cmd/mcp-server
./causent-mcp --root "$PWD" --db "$PWD/.causent/mcp.db"
```

The server exposes tools for starting and cancelling investigations, reading
investigations and evidence, inspecting hypotheses and experiments, and reading
patch and verification reports.

The server restricts repository roots, executable commands, request and
response sizes, timeouts, and environment variables. It is intended for local
use and is not the GitHub Actions integration.
