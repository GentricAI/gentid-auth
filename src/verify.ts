import { parseAgentId, resolveDiscovery, resolveJwks } from '@gentid/protocol';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import type { AgentContext } from './types';

const DEFAULT_API_URL = 'https://api.gentid.com';
const TOKEN_AUDIENCE = 'gentid-permission-token';

interface VerifyResponse {
  valid: true;
  agentId: string;
  agentName: string;
  owner: string;
  status: string;
  permissions: Record<string, unknown>;
  issuedAt: string;
  expiresAt: string;
}

/** Raw claim shape of a GentID permission token, as signed by delegation.service.ts. */
interface PermissionTokenClaims {
  sub: string;
  owner: string;
  name: string;
  status: string;
  permissions: Record<string, unknown>;
  iat: number;
  exp: number;
}

async function verifyViaRestEndpoint(token: string, apiUrl: string): Promise<AgentContext> {
  const res = await fetch(`${apiUrl.replace(/\/$/, '')}/api/v1/verification/verify-token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });

  const data = await res.json().catch(() => ({}) as Record<string, unknown>);

  if (!res.ok) {
    throw new Error((data as { error?: string }).error ?? `Token verification failed (${res.status})`);
  }

  const d = data as VerifyResponse;
  return {
    agentId: d.agentId,
    agentName: d.agentName,
    owner: d.owner,
    status: d.status,
    permissions: d.permissions ?? {},
    issuedAt: d.issuedAt,
    expiresAt: d.expiresAt,
  };
}

/**
 * Verifies a token locally against the issuing instance's published JWKS — the only
 * network calls are the (cached) discovery document and JWKS fetch, not a per-request
 * round trip to the issuer's verify-token endpoint.
 *
 * Returns null (rather than throwing) when the token isn't a discoverable protocol
 * token — e.g. a legacy `gentic:agent:` token — so the caller can fall back to
 * verifyViaRestEndpoint. Throws when the token *is* discoverable but fails
 * verification (bad signature, wrong audience, expired, etc).
 */
async function verifyViaDiscovery(token: string): Promise<AgentContext | null> {
  let claims: { sub?: string };
  try {
    claims = decodeJwt(token);
  } catch {
    return null;
  }

  const subject = claims.sub ? parseAgentId(claims.sub) : null;
  if (!subject || subject.legacy) return null;

  const protocol = /^localhost(:\d+)?$/.test(subject.issuerHost) ? 'http' : 'https';
  const discoveryDoc = await resolveDiscovery(subject.issuerHost, { protocol });
  const jwks = await resolveJwks(discoveryDoc, { protocol });

  const { kid } = decodeProtectedHeader(token);
  const jwk = jwks.keys.find((k) => k.kid === kid) ?? jwks.keys[0];
  if (!jwk) throw new Error(`No matching signing key published by issuer "${subject.issuerHost}"`);

  const publicKey = await importJWK(jwk, jwk.alg ?? 'EdDSA');
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: discoveryDoc.issuer,
    audience: TOKEN_AUDIENCE,
    algorithms: ['EdDSA'],
  });

  const c = payload as unknown as PermissionTokenClaims;
  return {
    agentId: c.sub,
    agentName: c.name,
    owner: c.owner,
    status: c.status,
    permissions: c.permissions ?? {},
    issuedAt: new Date(c.iat * 1000).toISOString(),
    expiresAt: new Date(c.exp * 1000).toISOString(),
  };
}

/**
 * Verifies a GentID permission token.
 *
 * If `apiUrl` is passed explicitly, behavior is unchanged from prior versions: the
 * token is verified by POSTing to that instance's verify-token endpoint.
 *
 * If `apiUrl` is omitted, the issuer is resolved from the token's agent id (new
 * `agent:<issuer-host>:...` format) via discovery, and the token is verified locally
 * against that issuer's published JWKS. Legacy tokens, or any discovery failure, fall
 * back to calling DEFAULT_API_URL's verify-token endpoint — identical to prior
 * versions' behavior when no apiUrl was configured.
 */
export async function verifyGentidToken(token: string, apiUrl?: string): Promise<AgentContext> {
  if (apiUrl) return verifyViaRestEndpoint(token, apiUrl);

  try {
    const viaDiscovery = await verifyViaDiscovery(token);
    if (viaDiscovery) return viaDiscovery;
  } catch {
    // Discovery/JWKS resolution failed, or the token failed local verification.
    // Fall through — the REST endpoint independently re-validates signature and
    // issuer, so this can't turn an invalid token into a valid one.
  }

  return verifyViaRestEndpoint(token, DEFAULT_API_URL);
}

export function extractToken(
  authHeader: string | null | undefined,
  tokenHeader: string | null | undefined,
): string | null {
  if (authHeader?.startsWith('GentID ')) return authHeader.slice(7);
  if (tokenHeader) return tokenHeader;
  return null;
}
