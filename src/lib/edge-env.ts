import { env } from 'cloudflare:workers';
import type { KVNamespace } from '@cloudflare/workers-types';

export interface EdgeEnv {
  IP_CACHE?: KVNamespace;
  PUBLIC_SITE_URL?: string;
  TURNSTILE_SECRET_KEY_MANAGED?: string;
  TURNSTILE_SECRET_KEY_NON_INTERACTIVE?: string;
}

export function getEdgeEnv(): EdgeEnv {
  return (env as unknown as EdgeEnv) || {};
}
