/**
 * Curated high-confidence ASN & ISP classification rules for JudgeIP.
 * Used in combination with live BGP/RDAP/Geo feeds to distinguish:
 * - Datacenter / Cloud / Hosting / VPS ASNs
 * - Consumer Residential Broadband ISPs
 * - Mobile Carrier Networks
 * - Known VPN / Commercial Proxy Transit Providers
 */

export type UsageType = 'residential' | 'mobile' | 'hosting' | 'business' | 'education' | 'cdn' | 'reserved';

export interface AsnProfile {
  asn: number;
  name: string;
  type: UsageType;
  registeredCountry: string;
  riskModifier: number; // Negative = penalty, Positive = trust bonus
  note?: string;
}

export const KNOWN_ASN_PROFILES: Record<number, AsnProfile> = {
  // Cloud, CDN & Datacenter Giants
  13335: { asn: 13335, name: 'Cloudflare, Inc.', type: 'cdn', registeredCountry: 'US', riskModifier: -35, note: 'Cloudflare Anycast / WARP Exit' },
  15169: { asn: 15169, name: 'Google LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -30, note: 'Google Cloud / Public Infrastructure' },
  396982: { asn: 396982, name: 'Google Cloud Platform', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'GCP Compute Engine' },
  16509: { asn: 16509, name: 'Amazon.com, Inc. (AWS)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'AWS EC2 / Lightsail Datacenter' },
  14618: { asn: 14618, name: 'Amazon AES (AWS)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'AWS US-East Datacenter' },
  8075: { asn: 8075, name: 'Microsoft Corporation (Azure)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'Microsoft Azure Cloud' },
  14061: { asn: 14061, name: 'DigitalOcean, LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'High-density VPS Hosting' },
  20473: { asn: 20473, name: 'The Constant Company (Vultr / Choopa)', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'Vultr VPS / Common Proxy Exit' },
  63949: { asn: 63949, name: 'Akamai Connected Cloud (Linode)', type: 'hosting', registeredCountry: 'US', riskModifier: -48, note: 'Linode VPS Datacenter' },
  24940: { asn: 24940, name: 'Hetzner Online GmbH', type: 'hosting', registeredCountry: 'DE', riskModifier: -48, note: 'Hetzner Dedicated / Cloud Hosting' },
  16276: { asn: 16276, name: 'OVH SAS', type: 'hosting', registeredCountry: 'FR', riskModifier: -48, note: 'OVHcloud Datacenter' },
  31898: { asn: 31898, name: 'Oracle Corporation (OCI)', type: 'hosting', registeredCountry: 'US', riskModifier: -48, note: 'Oracle Cloud Free/Paid Tier VPS' },
  45102: { asn: 45102, name: 'Alibaba US Technology (AliCloud)', type: 'hosting', registeredCountry: 'CN', riskModifier: -50, note: 'Alibaba Cloud International VPS' },
  132203: { asn: 132203, name: 'Tencent Building (Tencent Cloud)', type: 'hosting', registeredCountry: 'CN', riskModifier: -50, note: 'Tencent Cloud International VPS' },
  36352: { asn: 36352, name: 'ColoCrossing', type: 'hosting', registeredCountry: 'US', riskModifier: -55, note: 'Budget VPS Colocation (RackNerd / Proxy Exit)' },
  53667: { asn: 53667, name: 'FranTech Solutions (BuyVM)', type: 'hosting', registeredCountry: 'US', riskModifier: -52, note: 'Offshore VPS / Proxy Transit' },
  9009: { asn: 9009, name: 'M247 Europe SRL', type: 'hosting', registeredCountry: 'RO', riskModifier: -65, note: 'Major Commercial VPN Exit Backbone' },
  60068: { asn: 60068, name: 'Datacamp Limited (CDN77)', type: 'hosting', registeredCountry: 'GB', riskModifier: -65, note: 'Commercial VPN / Proxy Server Hosting' },
  212238: { asn: 212238, name: 'Datacamp Limited', type: 'hosting', registeredCountry: 'GB', riskModifier: -65, note: 'Commercial VPN Transit' },
  136787: { asn: 136787, name: 'Packethub S.A. (NordVPN)', type: 'hosting', registeredCountry: 'PA', riskModifier: -68, note: 'Commercial VPN Exit ASN' },

  // Tier-1 Genuine Residential & Mobile ISPs (Trust Bonus)
  7922: { asn: 7922, name: 'Comcast Cable Communications, LLC', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Tier-1 Cable Residential ISP (Xfinity)' },
  7018: { asn: 7018, name: 'AT&T Enterprises, LLC', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US AT&T Fiber / Residential Broadband' },
  701: { asn: 701, name: 'Verizon Business / Fios', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Verizon Fios Residential ISP' },
  20115: { asn: 20115, name: 'Charter Communications (Spectrum)', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Spectrum Residential Cable ISP' },
  21928: { asn: 21928, name: 'T-Mobile USA, Inc.', type: 'mobile', registeredCountry: 'US', riskModifier: +10, note: 'US 5G/LTE Carrier CGNAT / Home Internet' },
  22394: { asn: 22394, name: 'Cellco Partnership (Verizon Wireless)', type: 'mobile', registeredCountry: 'US', riskModifier: +10, note: 'US Verizon Wireless Mobile Network' },
  2856: { asn: 2856, name: 'British Telecommunications PLC (BT)', type: 'residential', registeredCountry: 'GB', riskModifier: +8, note: 'UK Incumbent Residential ISP' },
  3320: { asn: 3320, name: 'Deutsche Telekom AG', type: 'residential', registeredCountry: 'DE', riskModifier: +8, note: 'German Incumbent Residential ISP' },
  4713: { asn: 4713, name: 'NTT Communications / OCN', type: 'residential', registeredCountry: 'JP', riskModifier: +8, note: 'Japan Tier-1 Residential Fiber ISP' },
  17676: { asn: 17676, name: 'SoftBank Corp.', type: 'residential', registeredCountry: 'JP', riskModifier: +8, note: 'Japan SoftBank Broadband / Mobile' },
  3462: { asn: 3462, name: 'Chunghwa Telecom (HiNet)', type: 'residential', registeredCountry: 'TW', riskModifier: +8, note: 'Taiwan HiNet Residential Broadband' },
  4760: { asn: 4760, name: 'HKT Limited (Netvigator)', type: 'residential', registeredCountry: 'HK', riskModifier: +8, note: 'Hong Kong Residential Fiber ISP' },
  4134: { asn: 4134, name: 'Chinanet (China Telecom)', type: 'residential', registeredCountry: 'CN', riskModifier: +6, note: 'China Telecom Domestic Broadband' },
  4837: { asn: 4837, name: 'CHINA UNICOM China169 Backbone', type: 'residential', registeredCountry: 'CN', riskModifier: +6, note: 'China Unicom Domestic Broadband' },
  9808: { asn: 9808, name: 'China Mobile Communications Group', type: 'mobile', registeredCountry: 'CN', riskModifier: +6, note: 'China Mobile Domestic Broadband / 5G' },
};

const HOSTING_KEYWORDS = [
  'cloud', 'hosting', 'datacenter', 'data center', 'server', 'vps', 'dedi', 'colocation',
  'colo', 'linode', 'vultr', 'digitalocean', 'hetzner', 'ovh', 'choopa', 'sharktech',
  'psychz', 'zenlayer', 'cogent', 'hurricane electric', 'leaseweb', 'contabo', 'hostinger',
  'kamatera', 'aws', 'amazon', 'azure', 'google llc', 'alibaba', 'tencent', 'oracle',
  'm247', 'datacamp', 'tzulo', 'performive', 'quadranet', 'multacom', 'dmit', 'bandwagon',
  'it7 networks', 'clouvider', 'hybula', 'scaleway', 'upcloud', 'fly.io', 'fastly', 'akamai',
];

const MOBILE_KEYWORDS = [
  'wireless', 'mobile', 'cellular', 'cellco', 't-mobile', 'vodafone', 'orange', 'docomo',
  'kddi', 'rakuten mobile', 'starhub mobile', 'singtel mobile', 'ee limited', 'telefonica',
];

const EDUCATION_KEYWORDS = [
  'university', 'college', 'academic', 'education', 'research network', 'ceres', 'jisc', 'cern', 'ernet',
];

const CDN_KEYWORDS = [
  'cloudflare', 'fastly', 'akamai', 'cloudfront', 'bunny.net', 'cdn77', 'edgio', 'imperva',
];

export function classifyIspAndAsn(asn: number | null, orgText: string, upstreamHostingFlag?: boolean, upstreamMobileFlag?: boolean): UsageType {
  if (asn && KNOWN_ASN_PROFILES[asn]) {
    return KNOWN_ASN_PROFILES[asn].type;
  }
  const normalized = orgText.toLowerCase();
  if (CDN_KEYWORDS.some((kw) => normalized.includes(kw))) return 'cdn';
  if (upstreamHostingFlag || HOSTING_KEYWORDS.some((kw) => normalized.includes(kw))) return 'hosting';
  if (EDUCATION_KEYWORDS.some((kw) => normalized.includes(kw))) return 'education';
  if (upstreamMobileFlag || MOBILE_KEYWORDS.some((kw) => normalized.includes(kw))) return 'mobile';
  if (normalized.includes('telecom') || normalized.includes('broadband') || normalized.includes('cable') || normalized.includes('communications') || normalized.includes('fiber') || normalized.includes('fios')) {
    return 'residential';
  }
  return 'residential';
}
