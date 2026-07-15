# @gentid/auth

Express, Next.js, and Cloudflare Worker middleware for [GentID](https://gentid.com), the open
identity protocol for AI agents.

Accept verified AI agents from any organization in one line. Verification runs against the
**agent's own domain** with pure cryptography: the middleware resolves the issuing domain's
anchors from DNS and its signed `.well-known` document, then checks the certificate chain
locally. There is no central registry and no per-request call to any GentID service.

[![npm version](https://img.shields.io/npm/v/@gentid/auth.svg)](https://www.npmjs.com/package/@gentid/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## How it works

1. An agent attaches two headers to its request: `GentID-Envelope` (a signed, timestamped,
   nonced wrapper bound to the request body) and `GentID-Bundle` (its certificate chain).
2. The middleware resolves the agent's domain anchors (DNS TXT plus signed
   `/.well-known/gentid.json`, cached per TTL) via `@gentid/resolver`.
3. `@gentid/core`'s `verifyChain` checks the chain: signatures, validity windows, monotonic
   narrowing of scopes and spending ceilings, and revocation.
4. Your handler reads `req.gentid`. No shared secrets, no API keys, no phone-home.

```
Agent → GentID-Envelope + GentID-Bundle → @gentid/auth → req.gentid → your handler
```

## Installation

```bash
npm install @gentid/auth
```

Requires Node.js 20+ (WebCrypto Ed25519). Works in edge runtimes.

## Express

```ts
import express from 'express';
import { gentidAuth } from '@gentid/auth/express';

const app = express();

// Capture the raw body so the envelope's payload hash can be checked.
app.use(express.json({ verify: (req, _res, buf) => { (req as any).rawBody = buf; } }));

app.use('/api', gentidAuth());

app.post('/api/book', (req, res) => {
  const { id, domain, grants, assurance } = req.gentid!;
  // id        → "gentic:agent:delta.com:ops:rebooker-7"
  // domain    → "delta.com" (the trust anchor, from the agent's own DNS)
  // grants    → effective scopes and mandateCeiling after chain narrowing
  // assurance → 1 domain-verified, 2 org-verified, 3 transaction-proven
  res.json({ ok: true, bookedBy: id });
});
```

For money-moving routes, force strict revocation freshness. Stale or unknown revocation state
then becomes a hard deny, and there is deliberately no option to bypass it:

```ts
app.use('/api/payments', gentidAuth({ operationClass: 'financial' }));
```

## Mandates and HTTP 402

If a request carries a spending mandate, it is verified against the chain's ceilings and the
issuing org's designated enforcers, and exposed as `req.gentid.mandate`.

**Verified is not the same as enforceable.** Verification proves the mandate is authentic:
really issued, within its chain's ceilings, unexpired, unrevoked. Whether funds exist and
budgets have room is the job of the settlement institution named in the mandate. GentID never
holds balances.

Server side, charge for an action:

```ts
import { paymentRequiredHeaders } from '@gentid/auth';

res.status(402).set(paymentRequiredHeaders({
  amount: 12.5, currency: 'USD',
  payee: 'acme-travel.com',
  enforcersAccepted: ['atheries.com'],
}));
```

Client side, complete the escrow-then-retry flow with any enforcer implementing the neutral
`MandateEnforcerClient` interface:

```ts
import { fetchWith402 } from '@gentid/auth';

const resp = await fetchWith402(request, { mandate, enforcers, reference: envelope.id });
```

## Legacy tokens (v1 compatibility)

Requests without protocol headers fall back to the registry-era token path
(`Authorization: GentID <token>` or `X-GentID-Token`), verified against the issuing instance's
published JWKS and exposed as `req.agent`. Existing v1 integrations keep working unchanged
through the migration window. See the
[migration guide](https://gentid.com/docs#migration).

## Also in this family

- [`@gentid/core`](https://github.com/gentricai/gentid-core): the protocol standard as a
  library. Pure verification, zero dependencies.
- [`@gentid/node`](https://github.com/gentricai/gentid-node): become an issuer for your own
  domain in about 15 minutes.
- [Protocol specification](https://gentid.com/spec) and
  [conformance test vectors](https://github.com/010101G/gentid/tree/main/spec/test-vectors).

MIT.
