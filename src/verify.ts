import type { AgentContext } from './types';

const DEFAULT_API_URL = 'https://api.gentid.com';

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

export async function verifyGentidToken(token: string, apiUrl = DEFAULT_API_URL): Promise<AgentContext> {
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

export function extractToken(
  authHeader: string | null | undefined,
  tokenHeader: string | null | undefined,
): string | null {
  if (authHeader?.startsWith('GentID ')) return authHeader.slice(7);
  if (tokenHeader) return tokenHeader;
  return null;
}
