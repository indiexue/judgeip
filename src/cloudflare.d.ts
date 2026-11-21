declare module 'cloudflare:workers' {
  export const env: import('./lib/edge-env').EdgeEnv;
}
