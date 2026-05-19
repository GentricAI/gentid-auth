import type { GentidAuthOptions, AgentContext } from './types';
import { verifyGentidToken, extractToken } from './verify';

export type { AgentContext, GentidAuthOptions } from './types';

interface CloudflareCtx {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

type FetchHandler<Env = Record<string, unknown>> = (
  request: Request,
  env: Env,
  ctx: CloudflareCtx,
) => Response | Promise<Response>;

type AuthedFetchHandler<Env = Record<string, unknown>> = (
  request: Request,
  agent: AgentContext,
  env: Env,
  ctx: CloudflareCtx,
) => Response | Promise<Response>;

/**
 * Wrap a Cloudflare Worker fetch handler with GentID agent authentication.
 * The verified agent context is passed as the second argument.
 *
 * @example
 * // worker.ts
 * import { withGentidAuth } from '@gentid/auth/cloudflare';
 *
 * export default {
 *   fetch: withGentidAuth(async (request, agent, env, ctx) => {
 *     return Response.json({ agent: agent.agentName, permissions: agent.permissions });
 *   }),
 * };
 */
export function withGentidAuth<Env = Record<string, unknown>>(
  handler: AuthedFetchHandler<Env>,
  options: GentidAuthOptions = {},
): FetchHandler<Env> {
  const { apiUrl, required = true } = options;

  return async function (request: Request, env: Env, ctx: CloudflareCtx): Promise<Response> {
    const token = extractToken(
      request.headers.get('authorization'),
      request.headers.get('x-gentid-token'),
    );

    if (!token) {
      if (required) {
        return Response.json(
          { error: 'GentID token required', code: 'MISSING_TOKEN' },
          { status: 401 },
        );
      }
      return handler(request, null as unknown as AgentContext, env, ctx);
    }

    try {
      const agent = await verifyGentidToken(token, apiUrl);
      return handler(request, agent, env, ctx);
    } catch (err) {
      return Response.json(
        { error: err instanceof Error ? err.message : 'Invalid GentID token', code: 'INVALID_TOKEN' },
        { status: 401 },
      );
    }
  };
}
