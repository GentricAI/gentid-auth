// Protocol-native verification (v2, spec §5.2/§8.1) — the default path.
export {
  verifyGentidRequest,
  hasProtocolHeaders,
  httpPayloadHash,
  type GentIDContext,
  type ProtocolVerifyOptions,
  type HttpRequestLike,
} from './protocol';

// HTTP 402 payment binding (spec §8.2) and the neutral enforcer interface.
export {
  paymentRequiredHeaders,
  parsePaymentChallenge,
  fetchWith402,
  PaymentRequiredError,
  type PaymentChallenge,
  type MandateEnforcerClient,
  type EscrowProof,
} from './http402';

// Legacy registry-era token verification (compatibility shim, deprecated).
export { verifyGentidToken, extractToken } from './verify';
export type { AgentContext, GentidAuthOptions } from './types';
