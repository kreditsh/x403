// Express: ask before the handler runs. On allowed the decision rides on req.x403 and the
// response carries X403-Decision; on anything else the response is the decision itself,
// with the status the decision names.

import { HEADER_DECISION, encode } from "../headers.js";
import { statusFor } from "../registry.js";
import type { Decision } from "../types.js";
import { buildQuery, clientOf, postReceipt, timeoutDecision, type GateOptions, type ReceiptInput } from "./shared.js";

/** The slice of Express this middleware touches, so the package needs no Express types. */
export interface ExpressLikeRequest {
  get(name: string): string | undefined;
  x403?: Decision;
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
    let decision: Decision;
    let query;
    try {
      query = await buildQuery(req, headers, options);
      decision = await client.decide(query);
    } catch (error) {
      const fallback = options.onError ? await options.onError(error, req) : undefined;
      if (fallback) decision = fallback;
      else if (query) decision = timeoutDecision(query);
      else {
        next(error);
        return;
      }
    }
    await options.onDecision?.(decision, req);
    req.x403 = decision;
    res.set(HEADER_DECISION, encode(decision));
    const shadow = decision.mode === "shadow" || options.mode === "shadow";
    if (decision.decision === "allowed" || shadow || options.passThrough) {
      next();
      return;
    }
    res.status(decision.http_status ?? statusFor(decision)).json(decision);
  };
}

/** After execution: countersign and post the receipt for req.x403. */
export function receipt(options: { client: ExpressOptions["client"] }) {
  const client = clientOf(options);
  return (input: ReceiptInput) => postReceipt(client, input);
}
