import { env } from 'cloudflare:workers';
import type { KVNamespace } from '@cloudflare/workers-types';

export interface EdgeEnv {
  IP_CACHE?: KVNamespace;
  PUBLIC_SITE_URL?: string;
  TURNSTILE_SECRET_KEY_MANAGED?: string;
  TURNSTILE_SECRET_KEY_NON_INTERACTIVE?: string;
  /* 方案 B 可选高配额 / 商业情报源密钥（不配置时自动走方案 A 免费公开源）。每项都可以填多个，用逗号、空格或换行分开，轮流使用 */
  IPAPI_IS_KEY?: string;
  ABUSEIPDB_KEY?: string;
  PROXYCHECK_KEY?: string;
  CF_RADAR_TOKEN?: string;
}

export function getEdgeEnv(): EdgeEnv {
  return (env as unknown as EdgeEnv) || {};
}
