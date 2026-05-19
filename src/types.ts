/** Identity and permissions attached to a verified GentID agent token. */
export interface AgentContext {
  agentId: string;
  agentName: string;
  owner: string;
  status: string;
  permissions: Record<string, unknown>;
  issuedAt: string;
  expiresAt: string;
}

export interface GentidAuthOptions {
  /** Override the GentID API base URL. Defaults to https://api.gentid.com */
  apiUrl?: string;
  /**
   * If true (default), requests without a valid GentID token are rejected with 401.
   * If false, they pass through — use req.agent (Express) or getAgentFromHeaders() (Next.js) to check.
   */
  required?: boolean;
}
