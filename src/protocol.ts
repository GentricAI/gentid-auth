/**
 * Protocol-native verification — spec §8.1 (auth v2).
 *
 * Parses GentID-Envelope / GentID-Bundle headers, resolves the domain's anchors
 * via @gentid/resolver, and runs @gentid/core's verifyChain / verifyMandate.
 * No call to api.gentid.com — or to any GentID service — happens here. The only
 * network I/O is anchor/revocation resolution against the *agent's own domain*,
 * cached per TTL.
 */

import {
  Bundle,
  Envelope,
  Mandate,
  OperationClass,
  VerifiedIdentity,
  VerifiedMandate,
  b64urlDecode,
  hashPayload,
  parseGentId,
  verifyChain,
  verifyMandate,
} from '@gentid/core';
import { Resolver, ResolverOptions } from '@gentid/resolver';

/** What v2 attaches to the request — PIVOT C2. */
export interface GentIDContext {
  id: string;
  domain: string;
  path: string[];
  name: string;
  chain: VerifiedIdentity['chain'];
  grants: VerifiedIdentity['grants'];
  /** Tiers 0–3 per spec §9. Tiers 2–3 require recognized attestations in the bundle. */
  assurance: 0 | 1 | 2 | 3;
  revocationChecked: boolean;
  /**
   * Present when the request carried a verified mandate.
   *
   * verified ≠ enforceable: verification proves the mandate is authentic — really
   * issued, within its chain's ceilings, unexpired, unrevoked. Whether funds exist,
   * budgets have room, or human approval happened is the *enforcer's* job against
   * live state GentID does not hold (spec §7.3). Never treat this field as proof
   * that a payment will succeed.
   */
  mandate?: VerifiedMandate;
}

export interface ProtocolVerifyOptions {
  /** Operation class for revocation freshness (spec §6.4). Default "commit". */
  operationClass?: OperationClass;
  resolver?: Resolver;
  resolverOptions?: ResolverOptions;
  /** Attestation authorities this RP recognizes for tier 2 (spec §9). */
  trustedAuthorities?: string[];
  /** Replay guard; return true if (agent, nonce) already seen. Required in production. */
  seenNonce?: (agent: string, nonce: string) => boolean;
  now?: number;
}

export interface HttpRequestLike {
  method: string;
  /** Path + query, e.g. "/api/rebook?pnr=ABC123". */
  pathWithQuery: string;
  /** Raw body bytes; empty for GET/HEAD. */
  body: Uint8Array | string;
  headers: Record<string, string | string[] | undefined>;
}

function header(req: HttpRequestLike, name: string): string | undefined {
  const v = req.headers[name] ?? req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

function decodeHeaderJson<T>(value: string, what: string): T {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(value))) as T;
  } catch {
    throw new Error(`malformed ${what} header`);
  }
}

export function hasProtocolHeaders(req: HttpRequestLike): boolean {
  return header(req, 'GentID-Envelope') !== undefined;
}

/** Canonical payload-hash input for HTTP (spec §8.1): "<METHOD> <path+query>\n" + body. */
export async function httpPayloadHash(req: HttpRequestLike): Promise<string> {
  const bodyBytes =
    typeof req.body === 'string' ? new TextEncoder().encode(req.body) : req.body;
  const prefix = new TextEncoder().encode(`${req.method.toUpperCase()} ${req.pathWithQuery}\n`);
  const joined = new Uint8Array(prefix.length + bodyBytes.length);
  joined.set(prefix, 0);
  joined.set(bodyBytes, prefix.length);
  return hashPayload(joined);
}

const defaultResolver = new Resolver();

/**
 * Verify a protocol-native request. Throws on any verification failure;
 * returns the GentIDContext on success.
 */
export async function verifyGentidRequest(
  req: HttpRequestLike,
  opts: ProtocolVerifyOptions = {},
): Promise<GentIDContext> {
  const envHeader = header(req, 'GentID-Envelope');
  if (!envHeader) throw new Error('missing GentID-Envelope header');
  const bundleHeader = header(req, 'GentID-Bundle');
  if (!bundleHeader) throw new Error('missing GentID-Bundle header'); // caching path: PIVOT C-later

  const envelope = decodeHeaderJson<Envelope>(envHeader, 'GentID-Envelope');
  const bundle = decodeHeaderJson<Bundle>(bundleHeader, 'GentID-Bundle');

  const parsed = parseGentId(envelope.agent);
  if (parsed.legacy) {
    throw new Error('legacy identifiers use the legacy token path, not protocol headers');
  }

  const resolver =
    opts.resolver ?? (opts.resolverOptions ? new Resolver(opts.resolverOptions) : defaultResolver);
  const resolved = await resolver.resolveAnchors(parsed.domain!);

  const operationClass = opts.operationClass ?? 'commit';
  let revocationList = bundle.revocations;
  const needsFresh = operationClass !== 'read';
  if (needsFresh) {
    const maxStale =
      operationClass === 'financial'
        ? resolved.wellKnown.revocation.maxAge
        : resolved.wellKnown.revocation.refreshInterval;
    revocationList = await resolver.resolveRevocations(parsed.domain!, maxStale);
  }

  const expectedPayloadHash = await httpPayloadHash(req);

  const identity = await verifyChain(bundle, resolved.anchors, {
    now: opts.now,
    operationClass,
    envelope,
    expectedPayloadHash,
    seenNonce: opts.seenNonce,
    revocationList,
    wellKnown: resolved.wellKnown,
    anchorsCorroborated: resolved.dnsCorroborated,
    trustedAuthorities: opts.trustedAuthorities,
  });

  const ctx: GentIDContext = {
    id: identity.id,
    domain: identity.domain,
    path: identity.path,
    name: identity.name,
    chain: identity.chain,
    grants: identity.grants,
    assurance: identity.assurance,
    revocationChecked: identity.revocationChecked,
  };

  // Mandate awareness (PIVOT C3): financial class is forced inside verifyMandate.
  const m = envelope.mandate;
  if (m && typeof m === 'object') {
    const financialList = await resolver.resolveRevocations(
      parsed.domain!,
      resolved.wellKnown.revocation.maxAge,
    );
    ctx.mandate = await verifyMandate(m as Mandate, bundle, resolved.anchors, {
      now: opts.now,
      envelope,
      expectedPayloadHash,
      seenNonce: opts.seenNonce,
      revocationList: financialList,
      wellKnown: resolved.wellKnown,
      anchorsCorroborated: resolved.dnsCorroborated,
      trustedAuthorities: opts.trustedAuthorities,
    });
  }

  return ctx;
}
