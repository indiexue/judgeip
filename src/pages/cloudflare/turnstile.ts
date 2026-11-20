import type { APIRoute } from 'astro';
import { getEdgeEnv } from '../../lib/edge-env';
import { verifyTurnstile } from '../../lib/turnstile';

export const POST: APIRoute = ({ request }) => verifyTurnstile(request, getEdgeEnv());
