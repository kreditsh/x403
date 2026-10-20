export * from "./types.js";
export { canonicalize, hash, hashString, sha256, hex } from "./jcs.js";
export {
  base64url,
  fromBase64url,
  generateKey,
  thumbprint,
  sign,
  verify,
  verifyDecision,
  verifyReceipt,
  signReceipt,
  signOutcome,
  signQuery,
  decisionHash,
  type KeyPair,
  type SignOptions,
  type Verified,
  type VerifyResult,
} from "./jws.js";
export { registry, entryOf, groupOf, checkOf, effectOf, escalationOf, statusFor, NORMATIVE_STATUSES } from "./registry.js";
export {
  HEADER_REQUIRED,
  HEADER_PRESENTATION,
  HEADER_DECISION,
  HEADER_RISK_DECISION,
  AUTH_SCHEME,
  encode,
  decode,
  wwwAuthenticate,
  parseWwwAuthenticate,
  authorizationRisk,
  parseAuthorizationRisk,
  type Presentation,
  type Challenge,
} from "./headers.js";
export { X403, X403Error, VERSION, type ClientOptions } from "./client.js";
export { buildQuery, presentationOf, postReceipt, timeoutDecision, type GateOptions, type ReceiptInput } from "./middleware/shared.js";
