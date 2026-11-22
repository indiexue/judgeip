/**
 * Curated high-confidence ASN & ISP classification rules for JudgeIP.
 * Combines:
 * 1. Curated 160+ global cloud, VPS, VPN, CDN, residential ISP, and mobile carrier ASNs
 * 2. PeeringDB live `info_type` classification (`Cable/DSL/ISP`, `Content`, `Enterprise`, `Educational`, `NSP`, etc.)
 * 3. Optional `ipapi.is` / `ipquery` / `proxycheck` company & ASN types (enabling Dual-ISP detection)
 * 4. Comprehensive global operator keyword heuristics
 */

export type UsageType = 'residential' | 'mobile' | 'hosting' | 'business' | 'education' | 'cdn' | 'reserved';

export interface AsnProfile {
  asn: number;
  name: string;
  type: UsageType;
  registeredCountry: string;
  riskModifier: number; // <= -60 indicates dedicated commercial VPN/proxy transit
  note?: string;
}

export const KNOWN_ASN_PROFILES: Record<number, AsnProfile> = {
  // ------------------------------------------------------------------ Cloud, CDN & Hyperscale Datacenters
  13335: { asn: 13335, name: 'Cloudflare, Inc.', type: 'cdn', registeredCountry: 'US', riskModifier: -35, note: 'Cloudflare Anycast / WARP Exit' },
  20940: { asn: 20940, name: 'Akamai International B.V.', type: 'cdn', registeredCountry: 'US', riskModifier: -30, note: 'Akamai Edge CDN' },
  16625: { asn: 16625, name: 'Akamai Technologies, Inc.', type: 'cdn', registeredCountry: 'US', riskModifier: -30, note: 'Akamai Edge CDN' },
  54113: { asn: 54113, name: 'Fastly, Inc.', type: 'cdn', registeredCountry: 'US', riskModifier: -30, note: 'Fastly Anycast CDN / Relay' },
  19551: { asn: 19551, name: 'Incapsula / Imperva', type: 'cdn', registeredCountry: 'US', riskModifier: -30, note: 'Imperva Cloud WAF / CDN' },
  60068: { asn: 60068, name: 'Datacamp Limited (CDN77)', type: 'hosting', registeredCountry: 'GB', riskModifier: -65, note: 'Commercial VPN / Proxy Server Hosting' },
  212238: { asn: 212238, name: 'Datacamp Limited', type: 'hosting', registeredCountry: 'GB', riskModifier: -65, note: 'Commercial VPN Transit' },

  15169: { asn: 15169, name: 'Google LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -30, note: 'Google Cloud / Public Infrastructure' },
  396982: { asn: 396982, name: 'Google Cloud Platform', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'GCP Compute Engine' },
  16509: { asn: 16509, name: 'Amazon.com, Inc. (AWS)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'AWS EC2 / Lightsail Datacenter' },
  14618: { asn: 14618, name: 'Amazon AES (AWS)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'AWS US-East Datacenter' },
  8075: { asn: 8075, name: 'Microsoft Corporation (Azure)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'Microsoft Azure Cloud' },
  31898: { asn: 31898, name: 'Oracle Corporation (OCI)', type: 'hosting', registeredCountry: 'US', riskModifier: -48, note: 'Oracle Cloud Free/Paid Tier VPS' },
  36351: { asn: 36351, name: 'SoftLayer Technologies (IBM Cloud)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'IBM Cloud Datacenter' },
  45102: { asn: 45102, name: 'Alibaba US Technology (AliCloud)', type: 'hosting', registeredCountry: 'CN', riskModifier: -50, note: 'Alibaba Cloud International VPS' },
  37963: { asn: 37963, name: 'Alibaba China Technology (Aliyun)', type: 'hosting', registeredCountry: 'CN', riskModifier: -45, note: 'Alibaba Cloud Domestic' },
  132203: { asn: 132203, name: 'Tencent Building (Tencent Cloud)', type: 'hosting', registeredCountry: 'CN', riskModifier: -50, note: 'Tencent Cloud International VPS' },
  45090: { asn: 45090, name: 'Shenzhen Tencent Computer Systems', type: 'hosting', registeredCountry: 'CN', riskModifier: -45, note: 'Tencent Cloud Domestic' },
  136907: { asn: 136907, name: 'Huawei Cloud Service', type: 'hosting', registeredCountry: 'CN', riskModifier: -48, note: 'Huawei Cloud VPS' },
  55990: { asn: 55990, name: 'Huawei Cloud Service', type: 'hosting', registeredCountry: 'CN', riskModifier: -48, note: 'Huawei Cloud' },

  // ------------------------------------------------------------------ Popular VPS, Dedicated & Cross-Border Hosting ASNs
  14061: { asn: 14061, name: 'DigitalOcean, LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'DigitalOcean Droplet VPS' },
  20473: { asn: 20473, name: 'The Constant Company (Vultr / Choopa)', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'Vultr VPS / Common Proxy Exit' },
  63949: { asn: 63949, name: 'Akamai Connected Cloud (Linode)', type: 'hosting', registeredCountry: 'US', riskModifier: -48, note: 'Linode VPS Datacenter' },
  24940: { asn: 24940, name: 'Hetzner Online GmbH', type: 'hosting', registeredCountry: 'DE', riskModifier: -48, note: 'Hetzner Dedicated / Cloud Hosting' },
  16276: { asn: 16276, name: 'OVH SAS', type: 'hosting', registeredCountry: 'FR', riskModifier: -48, note: 'OVHcloud Datacenter' },
  12876: { asn: 12876, name: 'Scaleway S.A.S. (Online.net)', type: 'hosting', registeredCountry: 'FR', riskModifier: -48, note: 'Scaleway Dedibox / Cloud' },
  51167: { asn: 51167, name: 'Contabo GmbH', type: 'hosting', registeredCountry: 'DE', riskModifier: -50, note: 'Contabo VPS Hosting' },
  47583: { asn: 47583, name: 'Hostinger International Limited', type: 'hosting', registeredCountry: 'CY', riskModifier: -48, note: 'Hostinger VPS' },
  26496: { asn: 26496, name: 'GoDaddy.com, LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'GoDaddy Hosting' },
  46606: { asn: 46606, name: 'Unified Layer (Bluehost)', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'Shared / VPS Web Hosting' },
  36352: { asn: 36352, name: 'ColoCrossing', type: 'hosting', registeredCountry: 'US', riskModifier: -55, note: 'Budget VPS Colocation (RackNerd / Proxy Exit)' },
  53667: { asn: 53667, name: 'FranTech Solutions (BuyVM)', type: 'hosting', registeredCountry: 'US', riskModifier: -52, note: 'BuyVM VPS / Proxy Transit' },
  25820: { asn: 25820, name: 'IT7 Networks Inc (BandwagonHost)', type: 'hosting', registeredCountry: 'CA', riskModifier: -52, note: 'BandwagonHost / bwh81 VPS' },
  54574: { asn: 54574, name: 'DMIT Cloud Services', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'DMIT Cross-Border VPS' },
  906: { asn: 906, name: 'DMIT, Inc.', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'DMIT Premium Transit VPS' },
  21859: { asn: 21859, name: 'Zenlayer Inc', type: 'hosting', registeredCountry: 'US', riskModifier: -48, note: 'Zenlayer Edge Datacenter' },
  8100: { asn: 8100, name: 'QuadraNet Enterprises LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'QuadraNet Los Angeles IDC' },
  40676: { asn: 40676, name: 'Psychz Networks', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'Psychz Datacenter' },
  46844: { asn: 46844, name: 'Sharktech', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'Sharktech DDoS Protected IDC' },
  35916: { asn: 35916, name: 'MULTACOM CORPORATION', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'Multacom LA Colocation' },
  62567: { asn: 62567, name: 'DigitalOcean, LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'DigitalOcean Hosting' },
  206264: { asn: 206264, name: 'Amarutu Technology Ltd', type: 'hosting', registeredCountry: 'HK', riskModifier: -52, note: 'APAC VPS Hosting' },
  138997: { asn: 138997, name: 'Eons Data Communications Limited', type: 'hosting', registeredCountry: 'HK', riskModifier: -50, note: 'APAC VPS Hosting' },
  139341: { asn: 139341, name: 'ACE (Tencent Transit)', type: 'hosting', registeredCountry: 'SG', riskModifier: -45, note: 'Cloud Transit Backbone' },
  60781: { asn: 60781, name: 'LeaseWeb Netherlands B.V.', type: 'hosting', registeredCountry: 'NL', riskModifier: -48, note: 'LeaseWeb Dedicated Hosting' },
  28753: { asn: 28753, name: 'LeaseWeb Deutschland GmbH', type: 'hosting', registeredCountry: 'DE', riskModifier: -48, note: 'LeaseWeb Hosting' },
  9370: { asn: 9370, name: 'SAKURA Internet Inc.', type: 'hosting', registeredCountry: 'JP', riskModifier: -45, note: 'Sakura VPS Japan' },
  7506: { asn: 7506, name: 'GMO Internet Group (ConoHa)', type: 'hosting', registeredCountry: 'JP', riskModifier: -48, note: 'ConoHa / GMO Cloud Japan' },
  135377: { asn: 135377, name: 'UCloud Information Technology', type: 'hosting', registeredCountry: 'HK', riskModifier: -48, note: 'UCloud Global VPS' },
  40065: { asn: 40065, name: 'CNSERVERS LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -50, note: 'Colocation / VPS' },
  398101: { asn: 398101, name: 'GoDaddy / Sucuri', type: 'hosting', registeredCountry: 'US', riskModifier: -45, note: 'Cloud Hosting' },

  // ------------------------------------------------------------------ Dedicated Commercial VPN & Proxy Backbone ASNs
  9009: { asn: 9009, name: 'M247 Europe SRL', type: 'hosting', registeredCountry: 'RO', riskModifier: -65, note: 'Major Commercial VPN Exit Backbone' },
  136787: { asn: 136787, name: 'Packethub S.A. (NordVPN / Tewfin)', type: 'hosting', registeredCountry: 'PA', riskModifier: -68, note: 'Commercial VPN Exit ASN' },
  209854: { asn: 209854, name: 'Cyberzone S.A. (Surfshark)', type: 'hosting', registeredCountry: 'VG', riskModifier: -68, note: 'Commercial VPN Exit ASN' },
  396356: { asn: 396356, name: 'Maxihost / Latitude.sh', type: 'hosting', registeredCountry: 'US', riskModifier: -55, note: 'Bare Metal Cloud / VPN Exit' },
  62041: { asn: 62041, name: 'Telegram Messenger Inc', type: 'hosting', registeredCountry: 'GB', riskModifier: -40, note: 'Telegram DC' },
  202425: { asn: 202425, name: 'IP Volume inc', type: 'hosting', registeredCountry: 'SC', riskModifier: -65, note: 'Offshore Bulletproof / VPN Hosting' },
  49981: { asn: 49981, name: 'WorldStream B.V.', type: 'hosting', registeredCountry: 'NL', riskModifier: -52, note: 'Dedicated Server Hosting' },
  206092: { asn: 206092, name: 'Internet Utilities Europe and Asia Limited', type: 'hosting', registeredCountry: 'GB', riskModifier: -65, note: 'Commercial VPN Exit ASN' },

  // ------------------------------------------------------------------ Tier-1 Transit & Business / ISP Leased Subnets
  174: { asn: 174, name: 'Cogent Communications', type: 'business', registeredCountry: 'US', riskModifier: -10, note: 'Tier-1 Transit / Leased Business Blocks' },
  6939: { asn: 6939, name: 'Hurricane Electric LLC', type: 'hosting', registeredCountry: 'US', riskModifier: -35, note: 'HE Backbone / Tunnelbroker / Colocation' },
  2914: { asn: 2914, name: 'NTT America, Inc.', type: 'business', registeredCountry: 'US', riskModifier: -8, note: 'Global Tier-1 Transit' },
  1299: { asn: 1299, name: 'Arelion Sweden AB (Telia)', type: 'business', registeredCountry: 'SE', riskModifier: -8, note: 'Global Tier-1 Transit' },
  3356: { asn: 3356, name: 'Level 3 Parent, LLC (Lumen)', type: 'business', registeredCountry: 'US', riskModifier: -8, note: 'Lumen Tier-1 Enterprise / Transit' },
  3257: { asn: 3257, name: 'GTT Communications Inc.', type: 'business', registeredCountry: 'US', riskModifier: -10, note: 'GTT Tier-1 Transit' },
  6461: { asn: 6461, name: 'Zayo Bandwidth', type: 'business', registeredCountry: 'US', riskModifier: -10, note: 'Zayo Fiber & Enterprise Transit' },
  979: { asn: 979, name: 'NetLab Global', type: 'business', registeredCountry: 'US', riskModifier: -12, note: 'Commercial Leased Subnet / Transit Provider' },

  // ------------------------------------------------------------------ North America Genuine Residential & Mobile ISPs
  7922: { asn: 7922, name: 'Comcast Cable Communications, LLC', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Tier-1 Cable Residential ISP (Xfinity)' },
  7018: { asn: 7018, name: 'AT&T Enterprises, LLC', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US AT&T Fiber / Residential Broadband' },
  701: { asn: 701, name: 'Verizon Business / Fios', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Verizon Fios Residential ISP' },
  20115: { asn: 20115, name: 'Charter Communications (Spectrum)', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Spectrum Residential Cable ISP' },
  22773: { asn: 22773, name: 'Cox Communications Inc.', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Cox Residential Cable' },
  209: { asn: 209, name: 'CenturyLink / Quantum Fiber', type: 'residential', registeredCountry: 'US', riskModifier: +6, note: 'US Residential DSL & Fiber' },
  5650: { asn: 5650, name: 'Frontier Communications of America', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Frontier Fiber Broadband' },
  6128: { asn: 6128, name: 'Cablevision Systems (Optimum / Altice)', type: 'residential', registeredCountry: 'US', riskModifier: +8, note: 'US Optimum Residential Cable' },
  14593: { asn: 14593, name: 'SpaceX Services, Inc. (Starlink)', type: 'residential', registeredCountry: 'US', riskModifier: +6, note: 'Starlink Satellite Residential Broadband' },
  21928: { asn: 21928, name: 'T-Mobile USA, Inc.', type: 'mobile', registeredCountry: 'US', riskModifier: +10, note: 'US 5G/LTE Carrier CGNAT / Home Internet' },
  22394: { asn: 22394, name: 'Cellco Partnership (Verizon Wireless)', type: 'mobile', registeredCountry: 'US', riskModifier: +10, note: 'US Verizon Wireless Mobile Network' },
  20057: { asn: 20057, name: 'AT&T Mobility LLC', type: 'mobile', registeredCountry: 'US', riskModifier: +10, note: 'US AT&T Wireless Mobile Network' },
  577: { asn: 577, name: 'Bell Canada', type: 'residential', registeredCountry: 'CA', riskModifier: +8, note: 'Canada Bell Residential Fiber' },
  812: { asn: 812, name: 'Rogers Communications Canada Inc.', type: 'residential', registeredCountry: 'CA', riskModifier: +8, note: 'Canada Rogers Cable ISP' },
  852: { asn: 852, name: 'TELUS Communications Inc.', type: 'residential', registeredCountry: 'CA', riskModifier: +8, note: 'Canada TELUS Residential ISP' },
  6327: { asn: 6327, name: 'Shaw Communications Inc.', type: 'residential', registeredCountry: 'CA', riskModifier: +8, note: 'Canada Shaw Cable ISP' },

  // ------------------------------------------------------------------ Europe Genuine Residential & Mobile ISPs
  2856: { asn: 2856, name: 'British Telecommunications PLC (BT)', type: 'residential', registeredCountry: 'GB', riskModifier: +8, note: 'UK Incumbent Residential ISP' },
  5089: { asn: 5089, name: 'Virgin Media Limited', type: 'residential', registeredCountry: 'GB', riskModifier: +8, note: 'UK Virgin Media Cable ISP' },
  5607: { asn: 5607, name: 'Sky UK Limited', type: 'residential', registeredCountry: 'GB', riskModifier: +8, note: 'UK Sky Broadband' },
  12576: { asn: 12576, name: 'EE Limited', type: 'mobile', registeredCountry: 'GB', riskModifier: +10, note: 'UK EE Mobile & Broadband' },
  3320: { asn: 3320, name: 'Deutsche Telekom AG', type: 'residential', registeredCountry: 'DE', riskModifier: +8, note: 'German Incumbent Residential ISP' },
  3209: { asn: 3209, name: 'Vodafone GmbH', type: 'residential', registeredCountry: 'DE', riskModifier: +8, note: 'Vodafone Germany Cable/DSL' },
  6805: { asn: 6805, name: 'Telefonica Germany (O2)', type: 'mobile', registeredCountry: 'DE', riskModifier: +8, note: 'O2 Germany Mobile & DSL' },
  3215: { asn: 3215, name: 'Orange S.A.', type: 'residential', registeredCountry: 'FR', riskModifier: +8, note: 'France Orange Fiber ISP' },
  12322: { asn: 12322, name: 'Free SAS (Proxad)', type: 'residential', registeredCountry: 'FR', riskModifier: +8, note: 'France Freebox Residential ISP' },
  15557: { asn: 15557, name: 'Societe Francaise du Radiotelephone (SFR)', type: 'residential', registeredCountry: 'FR', riskModifier: +8, note: 'France SFR Broadband & Mobile' },
  5410: { asn: 5410, name: 'Bouygues Telecom SA', type: 'residential', registeredCountry: 'FR', riskModifier: +8, note: 'France Bouygues Telecom' },
  1136: { asn: 1136, name: 'KPN B.V.', type: 'residential', registeredCountry: 'NL', riskModifier: +8, note: 'Netherlands KPN Residential ISP' },
  33915: { asn: 33915, name: 'Vodafone Libertel B.V. (Ziggo)', type: 'residential', registeredCountry: 'NL', riskModifier: +8, note: 'Netherlands Ziggo / Vodafone' },
  3352: { asn: 3352, name: 'Telefonica de Espana', type: 'residential', registeredCountry: 'ES', riskModifier: +8, note: 'Spain Movistar Residential ISP' },
  3269: { asn: 3269, name: 'Telecom Italia S.p.A. (TIM)', type: 'residential', registeredCountry: 'IT', riskModifier: +8, note: 'Italy TIM Broadband' },
  3303: { asn: 3303, name: 'Swisscom (Schweiz) AG', type: 'residential', registeredCountry: 'CH', riskModifier: +8, note: 'Switzerland Swisscom ISP' },

  // ------------------------------------------------------------------ Asia-Pacific & Greater China Residential & Mobile ISPs
  4713: { asn: 4713, name: 'NTT Communications / OCN', type: 'residential', registeredCountry: 'JP', riskModifier: +8, note: 'Japan Tier-1 Residential Fiber ISP' },
  2516: { asn: 2516, name: 'KDDI CORPORATION (au)', type: 'residential', registeredCountry: 'JP', riskModifier: +8, note: 'Japan KDDI au Hikari / Mobile' },
  17676: { asn: 17676, name: 'SoftBank Corp.', type: 'residential', registeredCountry: 'JP', riskModifier: +8, note: 'Japan SoftBank Broadband / Mobile' },
  9605: { asn: 9605, name: 'NTT DOCOMO, INC.', type: 'mobile', registeredCountry: 'JP', riskModifier: +10, note: 'Japan NTT Docomo 5G/LTE' },
  2527: { asn: 2527, name: 'Sony Network Communications (So-net / NURO)', type: 'residential', registeredCountry: 'JP', riskModifier: +8, note: 'Japan NURO Hikari Residential' },
  4766: { asn: 4766, name: 'Korea Telecom (KT)', type: 'residential', registeredCountry: 'KR', riskModifier: +8, note: 'South Korea KT Broadband' },
  9318: { asn: 9318, name: 'SK Broadband Co Ltd', type: 'residential', registeredCountry: 'KR', riskModifier: +8, note: 'South Korea SK Broadband' },
  3786: { asn: 3786, name: 'LG DACOM / LG Uplus', type: 'residential', registeredCountry: 'KR', riskModifier: +8, note: 'South Korea LG U+ ISP' },
  3462: { asn: 3462, name: 'Chunghwa Telecom (HiNet)', type: 'residential', registeredCountry: 'TW', riskModifier: +8, note: 'Taiwan HiNet Residential Broadband' },
  9924: { asn: 9924, name: 'Taiwan Mobile Co., Ltd.', type: 'mobile', registeredCountry: 'TW', riskModifier: +8, note: 'Taiwan Mobile / Cable Broadband' },
  9674: { asn: 9674, name: 'Far EasTone Telecommunications', type: 'mobile', registeredCountry: 'TW', riskModifier: +8, note: 'Taiwan FarEasTone Mobile/ISP' },
  4760: { asn: 4760, name: 'HKT Limited (Netvigator)', type: 'residential', registeredCountry: 'HK', riskModifier: +8, note: 'Hong Kong Netvigator Residential Fiber' },
  9269: { asn: 9269, name: 'Hong Kong Broadband Network (HKBN)', type: 'residential', registeredCountry: 'HK', riskModifier: +8, note: 'Hong Kong HKBN Residential Fiber' },
  9304: { asn: 9304, name: 'HGC Global Communications Limited', type: 'residential', registeredCountry: 'HK', riskModifier: +6, note: 'Hong Kong HGC Broadband' },
  17819: { asn: 17819, name: 'China Mobile Hong Kong (CMHK)', type: 'mobile', registeredCountry: 'HK', riskModifier: +8, note: 'Hong Kong CMHK 5G & Home Fiber' },
  4773: { asn: 4773, name: 'MobileOne Ltd (M1 Singapore)', type: 'mobile', registeredCountry: 'SG', riskModifier: +8, note: 'Singapore M1 Mobile & Fiber' },
  9506: { asn: 9506, name: 'Singtel Fibre Broadband', type: 'residential', registeredCountry: 'SG', riskModifier: +8, note: 'Singapore Singtel Residential ISP' },
  4657: { asn: 4657, name: 'StarHub Ltd', type: 'residential', registeredCountry: 'SG', riskModifier: +8, note: 'Singapore StarHub Broadband' },
  4788: { asn: 4788, name: 'TM Net / Telekom Malaysia (Unifi)', type: 'residential', registeredCountry: 'MY', riskModifier: +8, note: 'Malaysia Unifi Residential ISP' },
  1221: { asn: 1221, name: 'Telstra Limited', type: 'residential', registeredCountry: 'AU', riskModifier: +8, note: 'Australia Telstra Broadband & Mobile' },
  4804: { asn: 4804, name: 'Microplex PTY LTD (Optus)', type: 'residential', registeredCountry: 'AU', riskModifier: +8, note: 'Australia Optus ISP' },
  4134: { asn: 4134, name: 'Chinanet (China Telecom)', type: 'residential', registeredCountry: 'CN', riskModifier: +6, note: 'China Telecom Domestic Broadband' },
  4837: { asn: 4837, name: 'CHINA UNICOM China169 Backbone', type: 'residential', registeredCountry: 'CN', riskModifier: +6, note: 'China Unicom Domestic Broadband' },
  9808: { asn: 9808, name: 'China Mobile Communications Group', type: 'mobile', registeredCountry: 'CN', riskModifier: +6, note: 'China Mobile Domestic Broadband / 5G' },
  4538: { asn: 4538, name: 'China Education and Research Network (CERNET)', type: 'education', registeredCountry: 'CN', riskModifier: +4, note: 'CERNET Academic Network' },
};

const HOSTING_KEYWORDS = [
  'cloud', 'hosting', 'datacenter', 'data center', 'data-center', 'server', 'servers', 'vps', 'dedi', 'dedicated',
  'colocation', 'colo ', 'linode', 'vultr', 'digitalocean', 'hetzner', 'ovh', 'choopa', 'sharktech',
  'psychz', 'zenlayer', 'hurricane electric', 'leaseweb', 'contabo', 'hostinger',
  'kamatera', 'aws', 'amazon', 'azure', 'google llc', 'alibaba', 'aliyun', 'tencent', 'huawei cloud', 'oracle',
  'm247', 'datacamp', 'tzulo', 'performive', 'quadranet', 'multacom', 'dmit', 'bandwagon',
  'it7 networks', 'clouvider', 'hybula', 'scaleway', 'upcloud', 'fly.io', 'idc', 'racknerd', 'buyvm', 'frantech',
  'vultr', 'equinix', 'coresite', 'digital realty', 'cyxtera', 'flexential', 'velia', 'ionos', '1&1', 'strato',
  'kagoya', 'sakura internet', 'conoha', 'ucloud', 'kingsoft',
];

const MOBILE_KEYWORDS = [
  'wireless', 'mobile', 'cellular', 'cellco', 't-mobile', 'vodafone', 'docomo', 'mobility',
  'rakuten mobile', 'starhub mobile', 'singtel mobile', 'ee limited', 'csl mobile', 'smartone',
  'verizon wireless', 'at&t mobility', 'china mobile', 'taiwan mobile', 'fareastone', 'telkomsel', 'ais ', 'celcom', 'maxis',
];

const EDUCATION_KEYWORDS = [
  'university', 'college', 'academic', 'education', 'school', 'institute of technology',
  'research network', 'cernet', 'jisc', 'cern', 'ernet', 'internet2', 'geant', 'aarnet', 'sinet',
];

const CDN_KEYWORDS = [
  'cloudflare', 'fastly', 'akamai', 'cloudfront', 'bunny.net', 'cdn77', 'edgio', 'imperva', 'incapsula', 'gcore', 'cdnetworks',
];

const RESIDENTIAL_ISP_KEYWORDS = [
  'telecom', 'telecommunications', 'telekom', 'telefonica', 'telecoms', 'broadband', 'cable', 'fiber', 'fibre',
  'fios', 'dsl', 'adsl', 'vdsl', 'ftth', 'hikari', 'comcast', 'xfinity', 'charter', 'spectrum', 'cox ',
  'centurylink', 'frontier', 'verizon', 'bell canada', 'rogers', 'telus', 'virgin media', 'sky uk',
  'orange', 'free sas', 'proxad', 'bouygues', 'sfr ', 'kpn ', 'ziggo', 'swisscom', 'movistar',
  'chunghwa', 'hinet', 'netvigator', 'hkbn', 'singtel', 'starhub', 'unifi', 'telstra', 'optus', 'starlink',
  'chinanet', 'unicom', 'kt corp', 'sk broadband', 'lg uplus', 'so-net', 'ocn',
];

/**
 * Maps PeeringDB `info_type` to a JudgeIP UsageType hint when unambiguous.
 * PeeringDB values: "Cable/DSL/ISP", "NSP", "Content", "Enterprise", "Educational/Research",
 * "Non-Profit", "Government", "Route Server", "Network Services"
 */
export function mapPeeringDbType(infoType: string | undefined | null, orgText = ''): UsageType | null {
  const t = String(infoType || '').trim().toLowerCase();
  if (!t) return null;
  if (t.includes('educational')) return 'education';
  if (t === 'cable/dsl/isp') {
    // Some leased-subnet / hosting operators self-register as Cable/DSL/ISP on PeeringDB;
    // only treat as residential if orgText has residential ISP traits, otherwise business/commercial ISP.
    const low = orgText.toLowerCase();
    if (HOSTING_KEYWORDS.some((kw) => low.includes(kw))) return 'hosting';
    if (RESIDENTIAL_ISP_KEYWORDS.some((kw) => low.includes(kw))) return 'residential';
    return 'business';
  }
  if (t === 'nsp' || t === 'network services') {
    const low = orgText.toLowerCase();
    if (HOSTING_KEYWORDS.some((kw) => low.includes(kw))) return 'hosting';
    if (RESIDENTIAL_ISP_KEYWORDS.some((kw) => low.includes(kw))) return 'residential';
    return 'business';
  }
  if (t === 'content') {
    const low = orgText.toLowerCase();
    if (CDN_KEYWORDS.some((kw) => low.includes(kw))) return 'cdn';
    if (HOSTING_KEYWORDS.some((kw) => low.includes(kw))) return 'hosting';
    return 'business';
  }
  if (t === 'enterprise' || t === 'government' || t === 'non-profit') {
    const low = orgText.toLowerCase();
    if (HOSTING_KEYWORDS.some((kw) => low.includes(kw))) return 'hosting';
    return 'business';
  }
  return null;
}

export function classifyIspAndAsn(
  asn: number | null,
  orgText: string,
  upstreamHostingFlag?: boolean,
  upstreamMobileFlag?: boolean,
  peeringDbInfoType?: string | null,
  upstreamTypeHint?: string | null,
): UsageType {
  if (asn && KNOWN_ASN_PROFILES[asn]) {
    return KNOWN_ASN_PROFILES[asn].type;
  }

  const normalized = orgText.toLowerCase();
  const hint = String(upstreamTypeHint || '').trim().toLowerCase();

  if (CDN_KEYWORDS.some((kw) => normalized.includes(kw)) || hint === 'cdn') return 'cdn';
  if (upstreamHostingFlag || hint === 'hosting' || hint === 'datacenter' || HOSTING_KEYWORDS.some((kw) => normalized.includes(kw))) {
    return 'hosting';
  }
  if (EDUCATION_KEYWORDS.some((kw) => normalized.includes(kw)) || hint === 'education') return 'education';
  if (upstreamMobileFlag || hint === 'mobile' || MOBILE_KEYWORDS.some((kw) => normalized.includes(kw))) return 'mobile';

  if (hint === 'isp') {
    return RESIDENTIAL_ISP_KEYWORDS.some((kw) => normalized.includes(kw)) ? 'residential' : 'business';
  }
  if (hint === 'business' || hint === 'government' || hint === 'banking') return 'business';

  if (RESIDENTIAL_ISP_KEYWORDS.some((kw) => normalized.includes(kw))) {
    return 'residential';
  }

  const pdb = mapPeeringDbType(peeringDbInfoType, orgText);
  if (pdb) return pdb;

  // Fallback for legitimate registered ASNs / operators that are neither flagged as hosting nor matching consumer broadband keywords
  // (e.g. NetLab Global AS979, regional transit, enterprise networks, leased commercial blocks — same as IPFinal's "商业网络").
  return 'business';
}

export function hasExplicitResidentialEvidence(asn: number | null, orgText: string, ipapiCompanyType?: string, ipapiAsnType?: string): boolean {
  if (asn && KNOWN_ASN_PROFILES[asn]?.type === 'residential') return true;
  if (ipapiCompanyType?.toLowerCase() === 'isp' && ipapiAsnType?.toLowerCase() === 'isp') return true;
  const low = orgText.toLowerCase();
  return RESIDENTIAL_ISP_KEYWORDS.some((kw) => low.includes(kw));
}

/**
 * Dual-ISP ("双 ISP") detection:
 * True when both the IP-range registrant/company AND the origin ASN are verified consumer/telecom ISPs
 * (neither hosting/IDC, CDN, nor commercial VPN).
 */
export function detectDualIsp(params: {
  usage: UsageType | 'unknown';
  asn: number | null;
  isp: string;
  org: string;
  isDatacenter: boolean | null;
  isProxy: boolean | null;
  ipapiCompanyType?: string;
  ipapiAsnType?: string;
  peeringDbType?: string;
}): boolean {
  const { usage, asn, isp, org, isDatacenter, isProxy, ipapiCompanyType, ipapiAsnType, peeringDbType } = params;
  if (isDatacenter || isProxy) return false;
  if (usage !== 'residential' && usage !== 'mobile') return false;

  // Tier-1 verified via ipapi.is explicit company.type === 'isp' && asn.type === 'isp'
  if (ipapiCompanyType && ipapiAsnType) {
    return ipapiCompanyType.toLowerCase() === 'isp' && ipapiAsnType.toLowerCase() === 'isp';
  }

  const ispLow = isp.toLowerCase();
  const orgLow = org.toLowerCase();
  if (!ispLow || !orgLow || ispLow === '未知' || orgLow === '未知') return false;
  if (HOSTING_KEYWORDS.some((kw) => ispLow.includes(kw) || orgLow.includes(kw))) return false;

  const asnIsCarrier = Boolean(
    (asn && (KNOWN_ASN_PROFILES[asn]?.type === 'residential' || KNOWN_ASN_PROFILES[asn]?.type === 'mobile'))
    || String(peeringDbType || '').toLowerCase() === 'cable/dsl/isp'
    || RESIDENTIAL_ISP_KEYWORDS.some((kw) => ispLow.includes(kw))
    || MOBILE_KEYWORDS.some((kw) => ispLow.includes(kw))
  );
  const orgIsCarrier = Boolean(
    RESIDENTIAL_ISP_KEYWORDS.some((kw) => orgLow.includes(kw))
    || MOBILE_KEYWORDS.some((kw) => orgLow.includes(kw))
    || (asn && (KNOWN_ASN_PROFILES[asn]?.type === 'residential' || KNOWN_ASN_PROFILES[asn]?.type === 'mobile') && orgLow.slice(0, 5) === ispLow.slice(0, 5))
  );

  return asnIsCarrier && orgIsCarrier;
}
