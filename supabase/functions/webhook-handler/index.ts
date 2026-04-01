import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, apikey",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

async function signPayload(secret: string, body: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function deliverWebhook(
  url: string,
  secret: string,
  event: string,
  payload: Record<string, unknown>,
  maxAttempts = 3
): Promise<{ success: boolean; attempts: number; lastError?: string }> {
  const body = JSON.stringify({
    event,
    payload,
    timestamp: new Date().toISOString(),
  });

  const signature = await signPayload(secret, body);

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-AuthFlow-Signature": `sha256=${signature}`,
          "X-AuthFlow-Event": event,
          "X-AuthFlow-Delivery": crypto.randomUUID(),
          "User-Agent": "AuthFlow-Webhook/1.0",
        },
        body,
        signal: AbortSignal.timeout(10_000),
      });

      if (res.ok) {
        return { success: true, attempts: attempt };
      }

      const errorText = await res.text();
      if (attempt < maxAttempts) {
        // Exponential backoff: 1s, 2s, 4s
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt - 1)));
      } else {
        return { success: false, attempts: attempt, lastError: `HTTP ${res.status}: ${errorText}` };
      }
    } catch (e) {
      if (attempt >= maxAttempts) {
        return { success: false, attempts: attempt, lastError: (e as Error).message };
      }
      await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt - 1)));
    }
  }

  return { success: false, attempts: maxAttempts };
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  let body: {
    app_id?: string;
    event?: string;
    payload?: Record<string, unknown>;
  };

  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { app_id, event, payload } = body;

  if (!app_id || !event || !payload) {
    return json({ error: "app_id, event, and payload are required" }, 400);
  }

  const VALID_EVENTS = ["user.created", "user.login", "user.updated", "user.deleted"];
  if (!VALID_EVENTS.includes(event)) {
    return json({ error: `Invalid event. Must be one of: ${VALID_EVENTS.join(", ")}` }, 400);
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  const { data: webhooks, error: fetchError } = await supabase
    .from("webhooks")
    .select("id, url, secret, events")
    .eq("app_id", app_id)
    .eq("active", true)
    .contains("events", [event]);

  if (fetchError) {
    return json({ error: "Failed to fetch webhooks: " + fetchError.message }, 500);
  }

  if (!webhooks || webhooks.length === 0) {
    return json({ dispatched: 0, results: [] });
  }

  const results = await Promise.all(
    webhooks.map(async (webhook: { id: string; url: string; secret: string; events: string[] }) => {
      const result = await deliverWebhook(webhook.url, webhook.secret, event, payload);
      return { webhook_id: webhook.id, url: webhook.url, ...result };
    })
  );

  const successCount = results.filter((r) => r.success).length;

  return json({
    dispatched: webhooks.length,
    succeeded: successCount,
    failed: webhooks.length - successCount,
    results,
  });
});
