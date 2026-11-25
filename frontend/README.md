# MAILOX frontend

React 19 + TypeScript + Vite single-page app for MAILOX. See the [root README](../README.md) for the full install.

## Development

```bash
npm install
npm run dev        # http://localhost:5173
```

The dev server proxies `/api` to the API at `http://localhost:8000` (see `vite.config.ts`). All API calls use the relative path `/api/v1`, so there is no API URL to configure. The proxy sets `X-Forwarded-For`, which the API uses for its loopback check.

The dev server listens on localhost only. Do not run it with `--host` / `0.0.0.0`: anyone who can reach it reaches the API through the proxy.

## Checks

```bash
npx tsc -b --noEmit   # type check
npm run lint          # oxlint
npm test              # vitest (jsdom)
npm run build         # production bundle in dist/
```

## Environment

| Variable | Used by | Purpose |
|---|---|---|
| `VITE_REQUEST_ACCESS_URL` | SaaS edition only | Link shown on the signup page to people without an invitation. Not needed for self-hosted installs. |

## Production image

`Dockerfile` builds the bundle and serves it with nginx (`nginx.conf`), which also proxies `/api/` to the `api` service of the root `docker-compose.yml`.
