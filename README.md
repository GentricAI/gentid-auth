# @gentid/auth

Express, Next.js, and Cloudflare Worker middleware for [GentID](https://gentid.com) — the trust infrastructure layer for AI agents.

Add AI agent support to any Node.js backend in one line. Verify agent identity, read scoped permissions, and know exactly who is acting on whose behalf.

[![npm version](https://img.shields.io/npm/v/@gentid/auth.svg)](https://www.npmjs.com/package/@gentid/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## How it works

1. Your AI agent fetches a signed JWT from GentID using `@gentid/sdk`
2. The agent sends it in the `Authorization: GentID <token>` header
3. `@gentid/auth` verifies it against the GentID API and populates `req.agent`
4. Your handler reads the verified identity and permissions — no shared secrets, no config

```
Agent → Authorization: GentID <token> → @gentid/auth → req.agent → your handler
```

## Installation

```bash
npm install @gentid/auth
```

Requires Node.js 18+. Peer dependencies: `express ≥ 4` or `next ≥ 13` depending on which integration you use.

---

## Express / Node.js

```typescript
import express from 'express';
import { gentidAuth } from '@gentid/auth/express';

const app = express();

// Protect all /api routes — 401 if no valid GentID token
app.use('/api', gentidAuth());

app.post('/api/book-flight', (req, res) => {
  const { agentId, agentName, owner, permissions } = req.agent!;
  //    agentId     — "gentic:agent:a3f9d2..."
  //    agentName   — "grack-assistant"
  //    owner       — "acme-corp"
  //    permissions — { travel_booking: true, max_transaction_usd: 1500 }

  res.json({ confirmed: true, bookedBy: agentName });
});
```

### Optional — allow both humans and agents

```typescript
// required: false — non-agent requests pass through, req.agent is undefined
app.use('/api', gentidAuth({ required: false }));

app.get('/api/search', (req, res) => {
  if (req.agent) {
    // AI agent request
  } else {
    // Regular human/app request
  }
});
```

### TypeScript — type `req.agent` project-wide

Add this once to your project:

```typescript
// global.d.ts
import type { AgentContext } from '@gentid/auth/express';
declare module 'express-serve-static-core' {
  interface Request { agent?: AgentContext; }
}
```

---

## Next.js (App Router)

### Route handler wrapper

```typescript
// app/api/book/route.ts
import { withGentidAuth } from '@gentid/auth/next';

export const POST = withGentidAuth(async (req, agent) => {
  return Response.json({
    confirmed: true,
    bookedBy:  agent.agentName,
    allowed:   agent.permissions['travel_booking'] === true,
  });
});

// Optional — allow non-agent requests
export const GET = withGentidAuth(async (req, agent) => {
  if (agent) return Response.json({ mode: 'agent', name: agent.agentName });
  return Response.json({ mode: 'human' });
}, { required: false });
```

### middleware.ts — protect entire route groups

```typescript
// middleware.ts
import { createGentidMiddleware } from '@gentid/auth/next';

export default createGentidMiddleware({ required: true });

export const config = {
  matcher: '/api/agent/:path*',
};
```

Read the agent in downstream route handlers:

```typescript
// app/api/agent/action/route.ts
import { getAgentFromHeaders } from '@gentid/auth/next';
import { type NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  const agent = getAgentFromHeaders(req.headers);
  if (!agent) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  return NextResponse.json({ agent });
}
```

---

## Cloudflare Worker

```typescript
// worker.ts
import { withGentidAuth } from '@gentid/auth/cloudflare';

interface Env {
  GENTID_API_URL?: string;
}

export default {
  fetch: withGentidAuth<Env>(
    async (request, agent, env, ctx) => {
      return Response.json({
        agent:       agent.agentName,
        owner:       agent.owner,
        permissions: agent.permissions,
      });
    },
    { required: true },
  ),
};
```

---

## Token flow (agent side)

Your agent fetches a token using [`@gentid/sdk`](https://www.npmjs.com/package/@gentid/sdk) and attaches it to every outgoing request:

```typescript
import { GentIDClient } from '@gentid/sdk';

const gentid = new GentIDClient({ apiKey: process.env.GENTID_API_KEY! });

// Get a short-lived signed permission token (1 hour TTL)
const { token } = await gentid.getToken(agentId);

// Attach to every outgoing request
const response = await fetch('https://yoursite.com/api/book-flight', {
  method: 'POST',
  headers: {
    'Authorization': `GentID ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ from: 'JFK', to: 'SFO' }),
});
```

The token header is also accepted as `X-GentID-Token` for environments where `Authorization` is reserved.

---

## AgentContext shape

After verification, the agent context contains:

```typescript
interface AgentContext {
  agentId:     string;                    // "gentic:agent:a3f9d2c1e8b4"
  agentName:   string;                    // "grack-assistant"
  owner:       string;                    // "acme-corp"
  status:      string;                    // "active"
  permissions: Record<string, unknown>;   // { travel_booking: true, max_transaction_usd: 1500 }
  issuedAt:    string;                    // ISO 8601
  expiresAt:   string;                    // ISO 8601
}
```

---

## Options

```typescript
interface GentidAuthOptions {
  /** Override the GentID API base URL. Defaults to https://api.gentid.com */
  apiUrl?: string;

  /**
   * If true (default), requests without a valid GentID token are rejected with 401.
   * If false, non-agent requests pass through — check req.agent to distinguish.
   */
  required?: boolean;
}
```

---

## Exports

| Import path | Use for |
|---|---|
| `@gentid/auth` | Core types and `verifyGentidToken` utility |
| `@gentid/auth/express` | Express / Node.js middleware |
| `@gentid/auth/next` | Next.js route handlers and middleware.ts |
| `@gentid/auth/cloudflare` | Cloudflare Workers |

---

## Links

- [GentID Documentation](https://gentid.com/docs)
- [Dashboard → Integrations](https://gentid.com/dashboard/integrations)
- [npm — @gentid/sdk](https://www.npmjs.com/package/@gentid/sdk)
- [GitHub — gentid-sdk](https://github.com/010101G/gentid-sdk)
