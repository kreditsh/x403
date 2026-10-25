// The authority API client. One class, the six calls of spec section 7, and offline
// verification against the authority's published keys.

import { decode, encode } from "./headers.js";
import { verifyDecision, type VerifyOptions, type VerifyResult } from "./jws.js";
import type { Authority, Decision, JWKS, Outcome, QueryInput, Receipt, RiskQuery } from "./types.js";

export const VERSION = "0.2";

export class X403Error extends Error {
  readonly status: number;
  readonly detail: unknown;
  constructor(status: number, detail: unknown) {
    super(`${status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    this.name = "X403Error";
    this.status = status;
    this.detail = detail;
  }
}

export interface ClientOptions {
  /** The authority's origin, e.g. https://api.kredit.sh. */
  authority: string;
  apiKey?: string;
  fetch?: typeof fetch;
  /** Extra headers on every request, e.g. a session header. */
  headers?: Record<string, string>;
}

export class X403 {
  readonly authority: string;
  private readonly apiKey?: string;
  private readonly fetchFn: typeof fetch;
  private readonly extra: Record<string, string>;
  private authorityDoc?: Promise<Authority>;
  private keys?: Promise<JWKS>;

  constructor(options: ClientOptions) {
    this.authority = options.authority.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.fetchFn = options.fetch ?? globalThis.fetch;
    this.extra = options.headers ?? {};
    if (!this.fetchFn) throw new Error("no fetch available; pass one in options");
  }

  static encode = encode;
  static decode = decode;

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json", ...this.extra };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;
    const res = await this.fetchFn(`${this.authority}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let payload: unknown = text;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      // a non-JSON body is reported as text
    }
    if (!res.ok) {
      const detail = payload && typeof payload === "object" && "detail" in payload ? (payload as { detail: unknown }).detail : payload;
      throw new X403Error(res.status, detail);
    }
    return payload as T;
  }

  /** Fill scheme and version so a caller passes only what varies. */
  static query(input: QueryInput): RiskQuery {
    return { scheme: "x403", version: VERSION, ...input };
  }

  decide(input: QueryInput): Promise<Decision> {
    return this.call<Decision>("POST", "/x403/decide", X403.query(input));
  }

  /** The same question with mode preflight: decide now, pay later citing the id. */
  preflight(input: QueryInput): Promise<Decision> {
    return this.call<Decision>("POST", "/x403/decide", X403.query({ ...input, mode: "preflight" }));
  }

  receipt(receipt: Receipt): Promise<Receipt> {
    return this.call<Receipt>("POST", "/x403/receipts", receipt);
  }

  outcome(outcome: Outcome): Promise<Outcome> {
    return this.call<Outcome>("POST", "/x403/outcomes", outcome);
  }

  get(id: string): Promise<Decision> {
    return this.call<Decision>("GET", `/x403/decisions/${encodeURIComponent(id)}`);
  }

  authorityDocument(): Promise<Authority> {
    this.authorityDoc ??= this.call<Authority>("GET", "/.well-known/x403/authority.json");
    return this.authorityDoc;
  }

  /** The authority's keys, fetched once from the address its document names. */
  jwks(): Promise<JWKS> {
    this.keys ??= (async () => {
      let url = `${this.authority}/.well-known/x403/jwks.json`;
      try {
        const doc = await this.authorityDocument();
        if (doc.jwks_url) url = doc.jwks_url;
      } catch {
        // without a document the conventional path still answers
      }
      const path = url.startsWith(this.authority) ? url.slice(this.authority.length) : url;
      return path.startsWith("/") ? this.call<JWKS>("GET", path) : this.fetchFn(url).then((r) => r.json() as Promise<JWKS>);
    })();
    return this.keys;
  }

  /**
   * Offline verification of a decision against the cached keys. Pass the executor's own id
   * and the payment about to run so a decision for another executor or another payment is void.
   */
  async verify(decision: Decision, options: VerifyOptions = {}): Promise<VerifyResult> {
    return verifyDecision(decision, await this.jwks(), options);
  }

  /** Forget cached keys, e.g. after a verify fails on an unknown kid. */
  reset(): void {
    this.keys = undefined;
    this.authorityDoc = undefined;
  }
}
