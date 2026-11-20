# JudgeIP (`judgeip.com`)

**JudgeIP** is an edge-native IP purity checker, RIR WHOIS native ISP verifier, and browser leak inspection tool built for **Cloudflare Workers**.

## Core Capabilities

- **0–100 Purity Score (`S / A / B / C / D`)**: Transparent breakdown based on ASN classification, RIR registration, and passive port/proxy checks.
- **Dual-Stack IPv4 Priority**: Automatically detects and prioritizes visitor IPv4 when browsers connect over IPv6, with one-click switching between IPv4 and IPv6 reports.
- **RIR WHOIS Native vs. Broadcasted IP Check**: Compares original RIR country registration (`ARIN / RIPE / APNIC / LACNIC / AFRINIC`) against current BGP GeoIP location.
- **Passive Port & Proxy Check (`Shodan InternetDB`)**: Checks for publicly exposed proxy/tunnel ports without intrusive active scanning.
- **Service Compatibility Reference**: Risk indicators for **TikTok**, **Claude / ChatGPT**, **Amazon / E-commerce**, **Netflix / Streaming**, and **Stripe / PayPal**.
- **Browser Leak Check**: Client-side WebRTC STUN ICE candidate inspection, local timezone match, browser language check, WebDriver flag, and edge RTT.
- **Built-in Terminal CLI**:
  - `curl -sL judgeip.com` (or `curl -sL judgeip.com/ip`) → plain-text IP
  - `curl -sL judgeip.com/json` → fast edge JSON metadata
  - `curl -s "https://judgeip.com/api/v1/verdict?ip=8.8.8.8"` → full purity & RIR JSON report

---

## Local Development

```bash
pnpm install
pnpm dev
```

Run unit tests & production Cloudflare bundle build:

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
