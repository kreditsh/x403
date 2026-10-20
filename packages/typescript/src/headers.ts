// The HTTP binding: X403-* headers carry base64url JSON without padding, and the
// auth-scheme binding carries the same objects under WWW-Authenticate: Risk.

import { base64url, fromBase64url } from "./jws.js";
import type { RiskQuery } from "./types.js";

export const HEADER_REQUIRED = "X403-Required";
export const HEADER_PRESENTATION = "X403-Presentation";
export const HEADER_DECISION = "X403-Decision";
export const HEADER_RISK_DECISION = "Risk-Decision";
export const AUTH_SCHEME = "Risk";

const decoder = new TextDecoder();

export function encode(value: unknown): string {
  return base64url(JSON.stringify(value));
}

export function decode<T = unknown>(text: string): T {
  return JSON.parse(decoder.decode(fromBase64url(text.trim()))) as T;
}

/** The presentation an agent sends: the hops and evidence, or the id of a prior preflight decision. */
export interface Presentation {
  actor?: RiskQuery["actor"];
  intent?: RiskQuery["intent"];
  evidence?: RiskQuery["evidence"];
  decision_ref?: string;
}

export interface Challenge {
  policy: string;
  realm?: string;
  /** A base64url risk query the agent must help satisfy. */
  request?: string;
  expires?: string;
}

function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** `WWW-Authenticate: Risk policy="…", realm="…", request="…", expires="…"` */
export function wwwAuthenticate(challenge: Challenge): string {
  const parts = [`policy=${quote(challenge.policy)}`];
  if (challenge.realm) parts.push(`realm=${quote(challenge.realm)}`);
  if (challenge.request) parts.push(`request=${quote(challenge.request)}`);
  if (challenge.expires) parts.push(`expires=${quote(challenge.expires)}`);
  return `${AUTH_SCHEME} ${parts.join(", ")}`;
}

export function parseWwwAuthenticate(header: string): Challenge | null {
  const m = /^\s*Risk\s+(.*)$/s.exec(header);
  if (!m) return null;
  const out: Record<string, string> = {};
  const re = /(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/g;
  let hit: RegExpExecArray | null;
  while ((hit = re.exec(m[1]))) out[hit[1]] = (hit[2] ?? hit[3] ?? "").replace(/\\(.)/g, "$1");
  if (!out.policy) return null;
  return { policy: out.policy, realm: out.realm, request: out.request, expires: out.expires };
}

/** `Authorization: Risk <base64url presentation>` */
export function authorizationRisk(presentation: Presentation): string {
  return `${AUTH_SCHEME} ${encode(presentation)}`;
}

export function parseAuthorizationRisk(header: string | null | undefined): Presentation | null {
  if (!header) return null;
  const m = /^\s*Risk\s+([A-Za-z0-9_-]+)\s*$/.exec(header);
  if (!m) return null;
  try {
    return decode<Presentation>(m[1]);
  } catch {
    return null;
  }
}
