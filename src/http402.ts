/**
 * HTTP 402 payment binding — spec §8.2.
 *
 * Server side: emit a 402 challenge naming price, payee, and accepted enforcers.
 * Client side: given a verified mandate and an enforcer client, complete the
 * escrow-then-retry flow.
 *
 * `MandateEnforcerClient` is a *neutral* interface: any regulated settlement
 * institution can implement it. Atheries ships the first adapter, but nothing
 * here knows about Atheries. GentID verifies mandates; enforcers enforce them —
 * balances, budgets, and escrow state live with the enforcer, never here.
 */

import type { Mandate } from '@gentid/core';

export interface PaymentChallenge {
  amount: number;
  currency: string;
  /** Payee identifier: a GentID id pattern or bare domain (spec §7.1 scope.payees). */
  payee: string;
  /** Enforcer domains the service will accept escrow proofs from. */
  enforcersAccepted: string[];
}

/** Headers for a 402 response (spec §8.2). */
export function paymentRequiredHeaders(c: PaymentChallenge): Record<string, string> {
  return {
    'GentID-Price': `${c.amount} ${c.currency}`,
    'GentID-Payee': c.payee,
    'GentID-Enforcers-Accepted': c.enforcersAccepted.join(', '),
  };
}

/** Parse a 402 response's challenge headers. Returns null if not a GentID 402. */
export function parsePaymentChallenge(
  headers: Record<string, string | string[] | undefined> | Headers,
): PaymentChallenge | null {
  const get = (name: string): string | undefined => {
    if (typeof (headers as Headers).get === 'function') {
      return (headers as Headers).get(name) ?? undefined;
    }
    const rec = headers as Record<string, string | string[] | undefined>;
    const v = rec[name] ?? rec[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  };
  const price = get('GentID-Price');
  const payee = get('GentID-Payee');
  const enforcers = get('GentID-Enforcers-Accepted');
  if (!price || !payee || !enforcers) return null;
  const m = price.trim().match(/^([0-9]+(?:\.[0-9]+)?)\s+([A-Z]{3})$/);
  if (!m) return null;
  return {
    amount: Number(m[1]),
    currency: m[2]!,
    payee,
    enforcersAccepted: enforcers.split(',').map((s) => s.trim()).filter(Boolean),
  };
}

/** An enforcer-signed escrow proof, carried on retry in the GentID-Escrow header. */
export interface EscrowProof {
  /** Opaque, enforcer-signed token; the service verifies it against the enforcer's anchors. */
  token: string;
  enforcer: string;
  escrowId: string;
}

/**
 * Neutral settlement-institution interface (PIVOT C4). Implementations talk to a
 * specific enforcer's API; the flow and types here are enforcer-agnostic and
 * documented in the spec repo (§7.4, §8.2).
 */
export interface MandateEnforcerClient {
  /** The enforcer's domain, e.g. "atheries.com". Must be a GentID-anchored org. */
  readonly enforcerDomain: string;
  /** Price/feasibility check before committing. */
  quote(args: {
    mandate: Mandate;
    amount: number;
    currency: string;
    payee: string;
  }): Promise<{ ok: boolean; reason?: string }>;
  /** Place funds in escrow under the mandate; returns a signed proof for retry. */
  escrow(args: {
    mandate: Mandate;
    amount: number;
    currency: string;
    payee: string;
    /** Idempotency key; SHOULD be the envelope nonce of the retried request. */
    reference: string;
  }): Promise<EscrowProof>;
  /** Release (or query) — used by payees/services, not the paying agent. */
  release(escrowId: string): Promise<{ outcome: 'settled' | 'refunded' | 'failed' }>;
  status(escrowId: string): Promise<{ state: string }>;
}

export class PaymentRequiredError extends Error {
  constructor(
    public challenge: PaymentChallenge,
    public response: Response,
  ) {
    super(`402 Payment Required: ${challenge.amount} ${challenge.currency} to ${challenge.payee}`);
    this.name = 'PaymentRequiredError';
  }
}

/**
 * Client-side escrow-then-retry (spec §8.2): performs `request`, and on a GentID
 * 402 whose accepted enforcers intersect the mandate's, escrows and retries once
 * with the GentID-Escrow header attached.
 *
 * `request` is called with the extra headers to merge into the retried request.
 */
export async function fetchWith402(
  request: (extraHeaders: Record<string, string>) => Promise<Response>,
  args: {
    mandate: Mandate;
    enforcers: MandateEnforcerClient[];
    /** Idempotency reference for the escrow (e.g. envelope nonce). */
    reference: string;
  },
): Promise<Response> {
  const first = await request({});
  if (first.status !== 402) return first;

  const challenge = parsePaymentChallenge(first.headers);
  if (!challenge) return first; // a 402, but not a GentID one

  const usable = args.enforcers.find(
    (e) =>
      challenge.enforcersAccepted.includes(e.enforcerDomain) &&
      args.mandate.enforcers.includes(e.enforcerDomain),
  );
  if (!usable) throw new PaymentRequiredError(challenge, first);

  if (
    args.mandate.limits.currency !== challenge.currency ||
    (args.mandate.limits.perTransaction !== undefined &&
      challenge.amount > args.mandate.limits.perTransaction)
  ) {
    throw new PaymentRequiredError(challenge, first);
  }

  const proof = await usable.escrow({
    mandate: args.mandate,
    amount: challenge.amount,
    currency: challenge.currency,
    payee: challenge.payee,
    reference: args.reference,
  });

  return request({
    'GentID-Escrow': btoa(JSON.stringify(proof)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  });
}
