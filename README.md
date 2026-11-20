# JudgeIP (`judgeip.com` × `ipnano.io`)

**JudgeIP** (IP判官) is an edge-native IP purity verdict, RIR native ISP lineage verifier, and protocol-level leak auditing platform built specifically for **Cloudflare Workers / Pages**.

## Core Capabilities

- **Explainable 0–100 Purity Verdict (`S / A / B / C / D`)**: Transparent scoring backed by verifiable network forensics instead of black-box numbers.
- **RIR WHOIS Native vs. Broadcasted IP Verification**: Cross-checks original RIR country registration (`ARIN / RIPE / APNIC / LACNIC / AFRINIC`) against live BGP GeoIP location to expose "fake native" broadcasted IPs.
- **Passive Port & Proxy Hygiene (`Shodan InternetDB`)**: Flags exposed SOCKS5, HTTP proxy, Shadowsocks, and WireGuard listener ports without active intrusive scanning.
- **Platform Survival Matrix**: Instant pass/warn/block simulation for **TikTok Creator/Shop**, **Claude / ChatGPT**, **Amazon / Etsy Seller**, **Netflix Originals/Local Unlock**, and **Stripe / PayPal**.
- **Client-Side Tunnel Audit**: In-browser WebRTC STUN ICE leak detection, system timezone vs. IP timezone alignment, navigator locale hygiene, WebDriver check, and Cloudflare edge TCP/HTTP RTT comparison.
- **Bilingual Programmatic SEO**: Native English (`/`) & Simplified Chinese (`/zh`), dedicated scenario landing pages (`/tiktok-ip-check`, `/claude-ip-check`, `/native-ip-check`), shareable IP forensic pages (`/ip/[ip]`), `hreflang`, JSON-LD, and `sitemap.xml`.
- **Companion `ipnano.io` CLI Worker**: Included under `workers/ipnano-cli` (`curl ipnano.io`, `curl ipnano.io/json`, `curl ipnano.io/8.8.8.8`).

---

## Project Structure

```text
judgeip/
├── src/
│   ├── components/VerdictDashboard.astro  # Full interactive verdict UI + client WebRTC/TZ probe
│   ├── layouts/BaseLayout.astro           # SEO head, OpenGraph, hreflang, JSON-LD
│   ├── lib/
│   │   ├── ip-utils.ts                    # IPv4/IPv6 parser & RFC bogon classifier
│   │   ├── asn-intelligence.ts            # Curated datacenter/VPN/residential ASN profiles
│   │   ├── verdict-engine.ts              # Multi-source RIR + Shodan + Geo fusion & scoring
│   │   └── i18n.ts                        # EN / ZH copy dictionary
│   └── pages/
│       ├── index.astro                    # English home (instant visitor IP verdict)
│       ├── zh/index.astro                 # Chinese home (/zh)
│       ├── ip/[ip].astro                  # Shareable SEO report for any IPv4/IPv6
│       ├── tiktok-ip-check.astro          # Scenario SEO landing page
│       ├── claude-ip-check.astro          # Scenario SEO landing page
│       ├── native-ip-check.astro          # Scenario SEO landing page
│       └── api/v1/
│           ├── verdict.ts                 # Public JSON Verdict API (/api/v1/verdict?ip=...)
│           └── ping.ts                    # Edge RTT & TLS handshake telemetry endpoint
├── workers/
│   └── ipnano-cli/                        # Companion Cloudflare Worker for ipnano.io CLI
├── astro.config.mjs                       # Astro + @astrojs/cloudflare SSR configuration
└── wrangler.toml                          # Cloudflare Worker deployment config
```

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

---

## Deploying to Cloudflare Edge

### Option A: Automatic Git Integration (Recommended — Zero Secrets Needed)
1. Open **Cloudflare Dashboard** → **Workers & Pages** → **Create** → **Import a repository** → select `indiexue/judgeip`.
2. Set build configuration:
   - **Build command**: `pnpm build`
   - **Deploy command**: `npx wrangler deploy`
3. Bind custom domain **`judgeip.com`** (and `www.judgeip.com`) under **Settings → Domains & Routes**.

### Option B: CLI Deployment
```bash
pnpm deploy          # Deploys judgeip.com main app
pnpm deploy:ipnano   # Deploys ipnano.io companion CLI worker
```
