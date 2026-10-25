// Express: ask before the handler runs. On allowed the decision rides on req.x403 and the
// response carries X403-Decision; on anything else the response is the decision itself,
// with the status the decision names. Every response that carries the header is no-store.

import { CACHE_CONTROL, HEADER_DECISION, encode } from "../headers.js";
import type { AnyDecision } from "../types.js";
import { buildQuery, clientOf, executorOf, localDecision, postReceipt, statusOf, type GateOptions, type ReceiptInput } from "./shared.js";

/** The slice of Express this middleware touches, so the package needs no Express types. */
export interface ExpressLikeRequest {
  get(name: string): string | undefined;
  x403?: AnyDecision;
  [k: string]: unknown;
}

export interface ExpressLikeResponse {
  status(code: number): this;
  set(name: string, value: string): this;
  json(body: unknown): unknown;
}

export type ExpressNext = (err?: unknown) => void;

export type ExpressOptions<Req extends ExpressLikeRequest = ExpressLikeRequest> = GateOptions<Req> & {
  /** With true, a non-allowed does not end the request; the handler reads req.x403 and decides. */
  passThrough?: boolean;
};

export function x403<Req extends ExpressLikeRequest = ExpressLikeRequest>(options: ExpressOptions<Req>) {
  const client = clientOf(options);
  return async function x403Gate(req: Req, res: ExpressLikeResponse, next: ExpressNext): Promise<void> {
    const headers = { get: (name: string) => req.get(name) };
    let decision: AnyDecision;
    let query;
    try {
      query = await buildQuery(req, headers, options);
      decision = await client.decide(query);
    } catch (error) {
      const fallback = options.onError ? await options.onError(error, req) : undefined;
      if (fallback) decision = fallback;
      else if (query) decision = await localDecision(query, executorOf(query, options), options.privateJwk);
      else {
        next(error);
        return;
      }
    }
    await options.onDecision?.(decision, req);
    req.x403 = decision;
    res.set(HEADER_DECISION, encode(decision));
    res.set("Cache-Control", CACHE_CONTROL);
    const shadow = ("mode" in decision && decision.mode === "shadow") || options.mode === "shadow";
    if (decision.decision === "allowed" || shadow || options.passThrough) {
      next();
      return;
    }
    res.status(statusOf(decision)).json(decision);
  };
}

/** After execution: countersign and post the receipt for req.x403. */
export function receipt(options: { client: ExpressOptions["client"] }) {
  const client = clientOf(options);
  return (input: ReceiptInput) => postReceipt(client, input);
}
