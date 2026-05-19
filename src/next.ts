import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import type { GentidAuthOptions, AgentContext } from './types';
import { verifyGentidToken, extractToken } from './verify';

export type { AgentContext, GentidAuthOptions } from './types';

// Header names used to forward agent context from middleware to route handlers
const H_AGENT_ID    = 'x-gentid-agent-id';
const H_AGENT_NAME  = 'x-gentid-agent-name';
const H_OWNER       = 'x-gentid-owner';
const H_STATUS      = 'x-gentid-status';
const H_PERMISSIONS = 'x-gentid-permissions';
const H_ISSUED_AT   = 'x-gentid-issued-at';
const H_EXPIRES_AT  = 'x-gentid-expires-at';

/**
 * Wrap a Next.js App Router route handler with GentID agent authentication.
 * The verified agent context is passed as the second argument.
 *
 * @example
 * // app/api/book-flight/route.ts
 * import { withGentidAuth } from '@gentid/auth/next';
 *
 * export const POST = withGentidAuth(async (req, agent) => {
 *   // agent.permissions, agent.agentName, etc.
 *   return Response.json({ booked: true, by: agent.agentName });
 * });
 */
export function withGentidAuth(
  handler: (req: NextRequest, agent: AgentContext) => Response | Promise<Response>,
  options: GentidAuthOptions = {},
) {
  const { apiUrl, required = true } = options;

  return async function (req: NextRequest): Promise<Response> {
    const token = extractToken(
      req.headers.get('authorization'),
      req.headers.get('x-gentid-token'),
    );

    if (!token) {
      if (required) {
        return NextResponse.json(
          { error: 'GentID token required', code: 'MISSING_TOKEN' },
          { status: 401 },
        );
      }
      return handler(req, null as unknown as AgentContext);
    }

    try {
      const agent = await verifyGentidToken(token, apiUrl);
      return handler(req, agent);
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : 'Invalid GentID token', code: 'INVALID_TOKEN' },
        { status: 401 },
      );
    }
  };
}

/**
 * Create a Next.js `middleware.ts` handler that validates GentID tokens and
 * forwards agent identity as request headers to downstream route handlers.
 *
 * Read the agent in a route handler with `getAgentFromHeaders(request.headers)`.
 *
 * @example
 * // middleware.ts
 * import { createGentidMiddleware } from '@gentid/auth/next';
 * export default createGentidMiddleware({ required: false });
 * export const config = { matcher: '/api/:path*' };
 */
export function createGentidMiddleware(options: GentidAuthOptions = {}) {
  const { apiUrl, required = true } = options;

  return async function gentidMiddleware(req: NextRequest): Promise<NextResponse> {
    const token = extractToken(
      req.headers.get('authorization'),
      req.headers.get('x-gentid-token'),
    );

    if (!token) {
      if (required) {
        return NextResponse.json(
          { error: 'GentID token required', code: 'MISSING_TOKEN' },
          { status: 401 },
        );
      }
      return NextResponse.next();
    }

    try {
      const agent = await verifyGentidToken(token, apiUrl);
      const headers = new Headers(req.headers);
      headers.set(H_AGENT_ID,    agent.agentId);
      headers.set(H_AGENT_NAME,  agent.agentName);
      headers.set(H_OWNER,       agent.owner);
      headers.set(H_STATUS,      agent.status);
      headers.set(H_PERMISSIONS, JSON.stringify(agent.permissions));
      headers.set(H_ISSUED_AT,   agent.issuedAt);
      headers.set(H_EXPIRES_AT,  agent.expiresAt);
      return NextResponse.next({ request: { headers } });
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : 'Invalid GentID token', code: 'INVALID_TOKEN' },
        { status: 401 },
      );
    }
  };
}

/**
 * Read the agent context forwarded by `createGentidMiddleware` from request headers.
 * Returns null if no agent headers are present.
 *
 * @example
 * // app/api/protected/route.ts
 * import { getAgentFromHeaders } from '@gentid/auth/next';
 *
 * export async function GET(req: NextRequest) {
 *   const agent = getAgentFromHeaders(req.headers);
 *   if (!agent) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
 *   return NextResponse.json({ agent });
 * }
 */
export function getAgentFromHeaders(headers: Headers): AgentContext | null {
  const agentId = headers.get(H_AGENT_ID);
  if (!agentId) return null;
  return {
    agentId,
    agentName: headers.get(H_AGENT_NAME) ?? '',
    owner:     headers.get(H_OWNER) ?? '',
    status:    headers.get(H_STATUS) ?? '',
    permissions: JSON.parse(headers.get(H_PERMISSIONS) ?? '{}') as Record<string, unknown>,
    issuedAt:  headers.get(H_ISSUED_AT) ?? '',
    expiresAt: headers.get(H_EXPIRES_AT) ?? '',
  };
}
