// A Cloudflare Worker in front of an x402 endpoint: preflight on HEAD, gate on POST.
// The decision id rides in the x402 PaymentPayload extensions, so the merchant that
// settles can check it against kredit's signature without a round trip.
import { withX403, preflight } from "@kredit/x403/fetch";
import type { Payment } from "@kredit/x403";

interface Env {
  KREDIT_API_KEY: string;
}

const payment = async (request: Request): Promise<Payment> => {
  const url = new URL(request.url);
  return {
    type: "payment",
    amount: url.searchParams.get("amount") ?? "0.10",
    currency: "USDC",
    rail: "x402",
    executor: { id: url.hostname },
    references: { payment_requirements_hash: request.headers.get("X-Payment-Requirements-Hash") as `sha256:${string}` },
  };
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const options = {
      client: { authority: "https://api.kredit.sh", apiKey: env.KREDIT_API_KEY },
      policyId: "api-metered-v1",
      budgetMs: 120,
      payment,
    };
    if (request.method === "HEAD" || request.method === "OPTIONS") return preflight(options)(request);
    return withX403(async (_req, decision) => {
      // The agent pays over x402 citing decision.id; this handler serves the resource.
      return new Response(JSON.stringify({ served: true, decision: decision.id }), {
        headers: { "content-type": "application/json" },
      });
    }, options)(request, env);
  },
};
