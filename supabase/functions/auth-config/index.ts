import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, apikey",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
  }

  const url = new URL(req.url);
  const key = url.searchParams.get("key");

  if (!key) {
    return json({ error: "Missing required parameter: key" }, 400);
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  // Fetch app by publishable key
  const { data: app, error: appError } = await supabase
    .from("apps")
    .select("id, name, description")
    .eq("publishable_key", key)
    .single();

  if (appError || !app) {
    return json({ error: "App not found" }, 404);
  }

  // Fetch enabled providers (without client_secret)
  const { data: providerConfigs } = await supabase
    .from("provider_configs")
    .select("provider, enabled, client_id")
    .eq("app_id", app.id)
    .eq("enabled", true);

  // Fetch allowed redirect URLs
  const { data: redirectUrls } = await supabase
    .from("redirect_urls")
    .select("url")
    .eq("app_id", app.id);

  const providers: string[] = ["email"]; // email always enabled
  const providerConfigsPublic: Array<{ provider: string; client_id: string }> = [];

  for (const cfg of providerConfigs || []) {
    if (cfg.enabled) {
      providers.push(cfg.provider);
      if (cfg.client_id) {
        providerConfigsPublic.push({ provider: cfg.provider, client_id: cfg.client_id });
      }
    }
  }

  return json({
    id: app.id,
    name: app.name,
    description: app.description,
    providers,
    provider_configs: providerConfigsPublic,
    redirect_urls: (redirectUrls || []).map((r: { url: string }) => r.url),
  });
});
