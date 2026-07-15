import type { GentidAuthOptions, AgentContext } from './types';
import { verifyGentidToken, extractToken } from './verify';
import {
  GentIDContext,
  ProtocolVerifyOptions,
  hasProtocolHeaders,
  verifyGentidRequest,
} from './protocol';

export type { AgentContext, GentidAuthOptions } from './types';
export type { GentIDContext } from './protocol';

// Minimal structural types — compatible with Express Request/Response/NextFunction
// without requiring @types/express as a compile-time dependency.

interface ExpressRequest {
  method: string;
  originalUrl?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  /** Raw body bytes, if captured (e.g. express.json({ verify }) or express.raw()). */
  rawBody?: Uint8Array;
  body?: unknown;
  agent?: AgentContext;
  gentid?: GentIDContext;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): ExpressResponse;
}

type ExpressNext = (err?: unknown) => void;

export interface GentidAuthV2Options extends GentidAuthOptions, ProtocolVerifyOptions {}

/**
 * Express middleware that authenticates GentID agents and attaches:
 *  - `req.gentid` — protocol-native identity (envelope + bundle verification, spec §5.2;
 *    federated: verified against the agent's own domain, no GentID API involved), and
 *  - `req.agent` — legacy registry-era token identity (compatibility shim).
 *
 * Protocol requests are detected by the `GentID-Envelope` header; anything else
 * falls back to the legacy `Authorization: GentID <token>` / `X-GentID-Token` path.
 *
 * For protocol requests the envelope's payloadHash covers the raw body: capture it
 * with `express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } })`.
 *
 * @example
 * import { gentidAuth } from '@gentid/auth/express';
 * app.use('/api', gentidAuth());
 */
export function gentidAuth(options: GentidAuthV2Options = {}) {
  const { apiUrl, required = true } = options;

  return async function gentidAuthMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNext,
  ): Promise<void> {
    // ---- Protocol path (spec §8.1) ----
    const reqLike = {
      method: req.method,
      pathWithQuery: req.originalUrl ?? req.url ?? '/',
      body: req.rawBody ?? (typeof req.body === 'string' ? req.body : ''),
      headers: req.headers,
    };
    if (hasProtocolHeaders(reqLike)) {
      try {
        req.gentid = await verifyGentidRequest(reqLike, options);
        next();
      } catch (err) {
        res.status(401).json({
          error: err instanceof Error ? err.message : 'GentID verification failed',
          code: 'INVALID_GENTID',
        });
      }
      return;
    }

    // ---- Legacy token path (registry-era compatibility, PIVOT §8) ----
    const auth = req.headers['authorization'];
    const tok = req.headers['x-gentid-token'];
    const token = extractToken(
      Array.isArray(auth) ? auth[0] : auth,
      Array.isArray(tok) ? tok[0] : tok,
    );

    if (!token) {
      if (required) {
        res.status(401).json({ error: 'GentID credentials required', code: 'MISSING_TOKEN' });
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
