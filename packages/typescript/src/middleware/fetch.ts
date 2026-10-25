// The fetch-style handler: a Cloudflare Worker, Hono, a Next route. Same gate as Express,
// on Request and Response. Every response that carries X403-Decision is no-store.

import { CACHE_CONTROL, HEADER_DECISION, encode } from "../headers.js";
import type { AnyDecision } from "../types.js";
import { buildQuery, clientOf, executorOf, localDecision, postReceipt, statusOf, type GateOptions, type ReceiptInput } from "./shared.js";

export type FetchHandler<Env = unknown> = (request: Request, decision: AnyDecision, env: Env) => Response | Promise<Response>;

export type FetchOptions<Env = unknown> = GateOptions<Request> & {
  /** With true, a non-allowed still reaches the handler, which reads the decision. */
  passThrough?: boolean;
  env?: Env;
};

function withDecisionHeader(response: Response, decision: AnyDecision): Response {
  const out = new Response(response.body, response);
  out.headers.set(HEADER_DECISION, encode(decision));
  out.headers.set("Cache-Control", CACHE_CONTROL);
  return out;
}

export function withX403<Env = unknown>(handler: FetchHandler<Env>, options: FetchOptions<Env>) {
  const client = clientOf(options);
  return async function gated(request: Request, env?: Env): Promise<Response> {
    let decision: AnyDecision;
    let query;
    try {
      query = await buildQuery(request, request.headers, options);
      decision = await client.decide(query);
    } catch (error) {
      const fallback = options.onError ? await options.onError(error, request) : undefined;
      if (fallback) decision = fallback;
      else if (query) decision = await localDecision(query, executorOf(query, options), options.privateJwk);
      else throw error;
    }
    await options.onDecision?.(decision, request);
    const shadow = ("mode" in decision && decision.mode === "shadow") || options.mode === "shadow";
    if (decision.decision === "allowed" || shadow || options.passThrough) {
      return withDecisionHeader(await handler(request, decision, (env ?? options.env) as Env), decision);
    }
    return new Response(JSON.stringify(decision), {
      status: statusOf(decision),
      headers: { "content-type": "application/json", "cache-control": CACHE_CONTROL, [HEADER_DECISION]: encode(decision) },
    });
  };
}

/** Preflight: HEAD or OPTIONS with X403-Presentation answers 200 plus X403-Decision and no body. */
export function preflight(options: GateOptions<Request>) {
  const client = clientOf(options);
  return async function preflightGate(request: Request): Promise<Response> {
    const query = await buildQuery(request, request.headers, { ...options, mode: "preflight" });
    const decision = await client.decide(query);
    return new Response(null, {
      status: decision.decision === "allowed" ? 200 : statusOf(decision),
      headers: { "cache-control": CACHE_CONTROL, [HEADER_DECISION]: encode(decision) },
    });
  };
}

export function receipt(options: { client: FetchOptions["client"] }) {
  const client = clientOf(options);
  return (input: ReceiptInput) => postReceipt(client, input);
}
