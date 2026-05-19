import type { GentidAuthOptions, AgentContext } from './types';
import { verifyGentidToken, extractToken } from './verify';

export type { AgentContext, GentidAuthOptions } from './types';

// Minimal structural types — compatible with Express Request/Response/NextFunction
// without requiring @types/express as a compile-time dependency.

interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  agent?: AgentContext;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): ExpressResponse;
}

type ExpressNext = (err?: unknown) => void;

/**
 * Express middleware that verifies GentID agent tokens and attaches the decoded
 * identity to `req.agent`.
 *
 * Token is read from `Authorization: GentID <token>` or `X-GentID-Token` header.
 *
 * To type `req.agent` project-wide, add to your `global.d.ts`:
 * ```ts
 * import type { AgentContext } from '@gentid/auth/express';
 * declare module 'express-serve-static-core' {
 *   interface Request { agent?: AgentContext; }
 * }
 * ```
 *
 * @example
 * import { gentidAuth } from '@gentid/auth/express';
 * app.use('/api', gentidAuth());
 *
 * app.get('/api/action', (req, res) => {
 *   res.json({ agent: req.agent });
 * });
 */
export function gentidAuth(options: GentidAuthOptions = {}) {
  const { apiUrl, required = true } = options;

  return async function gentidAuthMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNext,
  ): Promise<void> {
    const auth = req.headers['authorization'];
    const tok  = req.headers['x-gentid-token'];

    const token = extractToken(
      Array.isArray(auth) ? auth[0] : auth,
      Array.isArray(tok)  ? tok[0]  : tok,
    );

    if (!token) {
      if (required) {
        res.status(401).json({ error: 'GentID token required', code: 'MISSING_TOKEN' });
        return;
      }
      next();
      return;
    }

    try {
      req.agent = await verifyGentidToken(token, apiUrl);
      next();
    } catch (err) {
      res.status(401).json({
        error: err instanceof Error ? err.message : 'Invalid GentID token',
        code: 'INVALID_TOKEN',
      });
    }
  };
}
