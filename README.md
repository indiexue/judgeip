# JudgeIP (`judgeip.com`)

**JudgeIP** shows the registration, network type, proxy flags and reputation evidence for an IP address, plus browser leak and routing checks. It runs on **Cloudflare Workers**. Scores are rule-based estimates from the evidence that was available, not a guarantee that any platform will accept the IP.

## Core Capabilities

- **Rule-based score (5–99, grades `A+ / A / B / C / D / F`)**: Each deduction lists the upstream evidence behind it; scores are capped when reputation evidence is incomplete, and no score is given when key data is missing. Rules live in `src/lib/score-rules.ts` and are published at `/scoring`.
- **Dual-Stack IPv4 Priority**: Automatically detects and prioritizes visitor IPv4 when browsers connect over IPv6, with one-click switching between IPv4 and IPv6 reports.
- **RIR WHOIS Native vs. Broadcasted IP Check**: Compares original RIR country registration (`ARIN / RIPE / APNIC / LACNIC / AFRINIC`) against current BGP GeoIP location.
- **Passive Port & Proxy Check (`Shodan InternetDB`)**: Checks for publicly exposed proxy/tunnel ports without intrusive active scanning.
- **Scenario notes**: Rule-based hints for e-commerce, payments, AI apps, social media and streaming. They are not platform measurements or success rates.
- **Browser Leak Check**: Client-side WebRTC STUN ICE candidate inspection, local timezone match, browser language check, WebDriver flag, and edge RTT.
- **Built-in Terminal CLI**:
  - `curl -sL judgeip.com` (or `curl -sL judgeip.com/ip`) → plain-text IP
  - `curl -sL judgeip.com/json` → fast edge JSON metadata
  - `curl -sL judgeip.com/8.8.8.8` → plain-text report for any IP
  - `curl -s "https://judgeip.com/api/ipinfo?ip=8.8.8.8"` → full JSON lookup (`/api/v1/verdict` keeps the legacy envelope)
- **MCP server**: `POST /mcp` (Streamable HTTP, no key).

Data sources, cache times and rate limits are listed at `/data` and `/api-docs`. Lookups that reach upstream sources share one per-visitor allowance per minute across pages, APIs, CLI and MCP (`src/lib/rate-limit.ts`); over it, pages show basic details and APIs return 429.

---

## Local Development

```bash
pnpm install
pnpm dev
```

Run unit tests and the production build (the build also compiles the IPsum reputation index, which is served only to the Worker through the `ASSETS` binding; `src/worker.ts` returns 404 for public requests to it):

```bash
pnpm test
pnpm build
```

## Deployment

Connected directly to Cloudflare Workers Builds (`indiexue/judgeip`):
- **Build command**: `pnpm run build`
- **Deploy command**: `npx wrangler deploy`

### Turnstile runtime secrets

The managed and non-interactive widgets use separate production keys. Configure these as **runtime Worker Secrets**, not build variables:

- `TURNSTILE_SECRET_KEY_MANAGED`
- `TURNSTILE_SECRET_KEY_NON_INTERACTIVE`

Public sitekeys and expected actions are defined in `src/lib/turnstile.ts`. Missing secrets return an explicit configuration error; there is no test-key fallback. Never commit secret values or paste them into chat. Local tests use injected mock responses and do not require production secrets.
