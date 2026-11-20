import { env } from 'cloudflare:workers';

export interface EdgeEnv {
  IP_CACHE?: KVNamespace;
  PUBLIC_SITE_URL?: string;
}

export function getEdgeEnv(): EdgeEnv {
  return (env as unknown as EdgeEnv) || {};
}
