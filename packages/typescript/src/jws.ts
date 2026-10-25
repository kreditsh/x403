// Compact JWS with ES256 over the RFC 8785 form, on WebCrypto so the same code signs in
// Node, in a Worker and in a browser. Signatures are raw r||s, which is what JWS wants and
// what WebCrypto produces, so nothing is re-encoded.

import { canonicalize, hash, hex, sha256, utf8 } from "./jcs.js";
import type { Decision, Hash, JWK, JWKS, LocalDecision, Outcome, Payment, Receipt, RiskQuery, Subject } from "./types.js";

const ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

export function base64url(bytes: Uint8Array | string): string {
  const view = typeof bytes === "string" ? utf8(bytes) : bytes;
  let bin = "";
  for (const b of view) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const decoder = new TextDecoder();

export interface KeyPair {
  privateJwk: JWK;
  publicJwk: JWK;
  kid: string;
}

/** A fresh P-256 pair as JWKs, with the RFC 7638 thumbprint as kid. */
export async function generateKey(): Promise<KeyPair> {
  const pair = await crypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
  const privateJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JWK;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JWK;
  const kid = await thumbprint(publicJwk);
  delete privateJwk.key_ops;
  delete publicJwk.key_ops;
  delete privateJwk.ext;
  delete publicJwk.ext;
  return { privateJwk: { ...privateJwk, kid, alg: "ES256" }, publicJwk: { ...publicJwk, kid, alg: "ES256", use: "sig" }, kid };
}

/** RFC 7638: the thumbprint is over exactly these members, in this order. */
export async function thumbprint(jwk: JWK): Promise<string> {
  if (jwk.kty !== "EC") throw new TypeError("thumbprint: only EC keys");
  const text = canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return base64url(await sha256(text));
}

async function importPrivate(jwk: JWK): Promise<CryptoKey> {
  const { kid: _kid, alg: _alg, use: _use, ...bare } = jwk;
  return crypto.subtle.importKey("jwk", bare as JsonWebKey, ALG, false, ["sign"]);
}

async function importPublic(jwk: JWK): Promise<CryptoKey> {
  const { kid: _kid, alg: _alg, use: _use, d: _d, ...bare } = jwk;
  return crypto.subtle.importKey("jwk", bare as JsonWebKey, ALG, false, ["verify"]);
}

export interface SignOptions {
  kid?: string;
  /** JOSE typ, e.g. "x403-decision+jws". */
  typ?: string;
}

/** Sign the canonical form of `payload` as a compact JWS. */
export async function sign(payload: unknown, privateJwk: JWK, options: SignOptions = {}): Promise<string> {
  const kid = options.kid ?? privateJwk.kid ?? (await thumbprint(privateJwk));
  const header = canonicalize({ alg: "ES256", kid, ...(options.typ ? { typ: options.typ } : {}) });
  const signingInput = `${base64url(header)}.${base64url(canonicalize(payload))}`;
  const key = await importPrivate(privateJwk);
  const sig = await crypto.subtle.sign(SIGN, key, utf8(signingInput) as BufferSource);
  return `${signingInput}.${base64url(new Uint8Array(sig))}`;
}

export interface Verified {
  header: { alg: string; kid?: string; typ?: string };
  payload: unknown;
  payloadText: string;
}

function pickKey(jwks: JWKS | JWK, kid?: string): JWK {
  if (!("keys" in jwks)) return jwks;
  const keys = (jwks as JWKS).keys.filter((k) => k.kty === "EC" && k.crv === "P-256");
  const match = kid ? keys.find((k) => k.kid === kid) : undefined;
  const key = match ?? (keys.length === 1 ? keys[0] : undefined);
  if (!key) throw new Error(kid ? `no key with kid ${kid}` : "no single P-256 key to verify with");
  return key;
}

/** Verify a compact JWS against a key set and return its header and payload. Throws when it does not verify. */
export async function verify(jws: string, jwks: JWKS | JWK): Promise<Verified> {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("not a compact JWS");
  const [h, p, s] = parts;
  const header = JSON.parse(decoder.decode(fromBase64url(h))) as Verified["header"];
  if (header.alg !== "ES256") throw new Error(`unsupported alg ${header.alg}`);
  const key = await importPublic(pickKey(jwks, header.kid));
  const ok = await crypto.subtle.verify(SIGN, key, fromBase64url(s) as BufferSource, utf8(`${h}.${p}`) as BufferSource);
  if (!ok) throw new Error("signature does not verify");
  const payloadText = decoder.decode(fromBase64url(p));
  return { header, payload: JSON.parse(payloadText), payloadText };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  kid?: string;
}

/** What a verifier knows about where and for what a decision is being presented. */
export interface VerifyOptions {
  now?: Date;
  /** The executor's own id: a decision whose audience is another executor is void here. */
  audience?: string;
  /** The payment about to be executed: a decision issued for another payment is void for it. */
  payment?: Payment;
}

/** The hash a decision's subject carries: the payment object as presented. */
export async function paymentHash(payment: Payment): Promise<Hash> {
  return hash(payment);
}

/** The subject a decision for `payment` must carry. */
export async function subjectOf(payment: Payment): Promise<Subject> {
  return { payment_ref: await paymentHash(payment), amount: payment.amount, currency: payment.currency, executor_id: payment.executor.id };
}

async function checkBinding(decision: { subject?: Subject; audience?: string }, options: VerifyOptions, kid?: string): Promise<VerifyResult | null> {
  if (options.audience !== undefined && decision.audience !== options.audience) return { ok: false, reason: "audience_mismatch", kid };
  if (options.payment) {
    const want = await subjectOf(options.payment);
    const got = decision.subject;
    if (!got || got.payment_ref !== want.payment_ref || got.amount !== want.amount || got.currency !== want.currency || got.executor_id !== want.executor_id) {
      return { ok: false, reason: "subject_mismatch", kid };
    }
  }
  return null;
}

/**
 * A decision verifies when its decision_sig is a valid ES256 signature by one of the
 * authority's keys over the object without decision_sig, it has not expired, and, when the
 * verifier says where it is being presented, its audience and subject are this executor and
 * this payment.
 */
export async function verifyDecision(decision: Decision, jwks: JWKS | JWK, options: Date | VerifyOptions = {}): Promise<VerifyResult> {
  const opts: VerifyOptions = options instanceof Date ? { now: options } : options;
  const now = opts.now ?? new Date();
  if (!decision.decision_sig) return { ok: false, reason: "unsigned" };
  const { decision_sig, ...body } = decision;
  let verified: Verified;
  try {
    verified = await verify(decision_sig, jwks);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
  // The signed payload must be this object, byte for byte in canonical form: a decision
  // whose fields were edited after signing carries a signature over something else.
  if (verified.payloadText !== canonicalize(body)) return { ok: false, reason: "object differs from signed payload", kid: verified.header.kid };
  if (decision.expires_at && new Date(decision.expires_at).getTime() <= now.getTime()) {
    return { ok: false, reason: "decision_expired", kid: verified.header.kid };
  }
  const bound = await checkBinding(decision, opts, verified.header.kid);
  if (bound) return bound;
  return { ok: true, kid: verified.header.kid };
}

/** Sign a local decision: local_sig is by the executor over the object without local_sig. */
export async function signLocalDecision(local: Omit<LocalDecision, "local_sig">, privateJwk: JWK, kid?: string): Promise<LocalDecision> {
  const { local_sig: _drop, ...body } = local as LocalDecision;
  const local_sig = await sign(body, privateJwk, { kid: kid ?? local.executor.kid, typ: "x403-local+jws" });
  return { ...body, local_sig };
}

/** A local decision verifies against the executor's keys, never an authority's, and is never an allow. */
export async function verifyLocalDecision(local: LocalDecision, jwks: JWKS | JWK, options: VerifyOptions = {}): Promise<VerifyResult> {
  if (local.local !== true) return { ok: false, reason: "not a local decision" };
  if (local.decision === ("allowed" as string)) return { ok: false, reason: "a local decision is never an allow" };
  if (!local.local_sig) return { ok: false, reason: "unsigned" };
  const { local_sig, ...body } = local;
  let verified: Verified;
  try {
    verified = await verify(local_sig, jwks);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
  if (verified.payloadText !== canonicalize(body)) return { ok: false, reason: "object differs from signed payload", kid: verified.header.kid };
  const bound = await checkBinding(local, options, verified.header.kid);
  if (bound) return bound;
  return { ok: true, kid: verified.header.kid };
}

/** Countersign a receipt: executor_sig is over the receipt without executor_sig. */
export async function signReceipt(receipt: Omit<Receipt, "executor_sig">, privateJwk: JWK, kid?: string): Promise<Receipt> {
  const { executor_sig: _drop, ...body } = receipt as Receipt;
  const executor_sig = await sign(body, privateJwk, { kid: kid ?? receipt.executor.kid, typ: "x403-receipt+jws" });
  return { ...body, executor_sig };
}

export async function signOutcome(outcome: Omit<Outcome, "sig">, privateJwk: JWK, kid?: string): Promise<Outcome> {
  const { sig: _drop, ...body } = outcome as Outcome;
  const sig = await sign(body, privateJwk, { kid: kid ?? outcome.reporter.kid, typ: "x403-outcome+jws" });
  return { ...body, sig };
}

export async function signQuery(query: Omit<RiskQuery, "requester_sig">, privateJwk: JWK, kid?: string): Promise<RiskQuery> {
  const { requester_sig: _drop, ...body } = query as RiskQuery;
  const requester_sig = await sign(body, privateJwk, { kid: kid ?? query.requester?.kid, typ: "x403-query+jws" });
  return { ...body, requester_sig };
}

/** Verify a receipt's countersignature against the executor's keys. */
export async function verifyReceipt(receipt: Receipt, jwks: JWKS | JWK): Promise<VerifyResult> {
  if (!receipt.executor_sig) return { ok: false, reason: "unsigned" };
  const { executor_sig, ...body } = receipt;
  try {
    const v = await verify(executor_sig, jwks);
    if (v.payloadText !== canonicalize(body)) return { ok: false, reason: "object differs from signed payload", kid: v.header.kid };
    return { ok: true, kid: v.header.kid };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

/** The hash a receipt must carry: the decision as signed, decision_sig included. */
export async function decisionHash(decision: Decision): Promise<Hash> {
  return `sha256:${hex(await sha256(canonicalize(decision)))}`;
}
