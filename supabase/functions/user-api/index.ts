import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
import { verify, getNumericDate } from "https://deno.land/x/djwt@v2.8/mod.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const JWT_SECRET = Deno.env.get("JWT_SECRET")!;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, apikey",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

function error(msg: string, status = 400): Response {
  return json({ error: msg }, status);
}

async function getCryptoKey(): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function authenticate(
  req: Request
): Promise<{ userId: string; appId: string; email: string } | null> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  try {
    const key = await getCryptoKey();
    const payload = await verify(token, key) as Record<string, unknown>;
    if (
      typeof payload.sub === "string" &&
      typeof payload.app_id === "string" &&
      typeof payload.email === "string" &&
      typeof payload.exp === "number" &&
      payload.exp > getNumericDate(0)
    ) {
      return { userId: payload.sub, appId: payload.app_id, email: payload.email };
    }
    return null;
  } catch {
    return null;
  }
}

async function dispatchWebhook(
  supabase: ReturnType<typeof createClient>,
  appId: string,
  event: string,
  payload: Record<string, unknown>
): Promise<void> {
  const { data: webhooks } = await supabase
    .from("webhooks")
    .select("*")
    .eq("app_id", appId)
    .eq("active", true)
    .contains("events", [event]);

  if (!webhooks?.length) return;

  for (const webhook of webhooks) {
    const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", enc.encode(webhook.secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
    const signature = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");

    let attempts = 0;
    while (attempts < 3) {
      try {
        const res = await fetch(webhook.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-AuthFlow-Signature": signature,
            "X-AuthFlow-Event": event,
          },
          body,
        });
        if (res.ok) break;
      } catch (_) { /* retry */ }
      attempts++;
      if (attempts < 3) await new Promise(r => setTimeout(r, 1000 * attempts));
    }
  }
}

// ── HANDLERS ──────────────────────────────────────────────────────────────────

async function handleGetMe(
  supabase: ReturnType<typeof createClient>,
  userId: string
): Promise<Response> {
  const { data, error: err } = await supabase
    .from("app_users")
    .select("id, email, name, avatar_url, provider, metadata, created_at, updated_at")
    .eq("id", userId)
    .single();

  if (err || !data) return error("User not found", 404);
  return json(data);
}

async function handlePatchMe(
  req: Request,
  supabase: ReturnType<typeof createClient>,
  userId: string,
  appId: string
): Promise<Response> {
  let body: { name?: string; avatar_url?: string; metadata?: Record<string, unknown> };
  try { body = await req.json(); } catch { return error("Invalid JSON body"); }

  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (body.name !== undefined) updates.name = body.name;
  if (body.avatar_url !== undefined) updates.avatar_url = body.avatar_url;
  if (body.metadata !== undefined) {
    const { data: existing } = await supabase
      .from("app_users").select("metadata").eq("id", userId).single();
    updates.metadata = { ...(existing?.metadata || {}), ...body.metadata };
  }

  const { data, error: err } = await supabase
    .from("app_users")
    .update(updates)
    .eq("id", userId)
    .select("id, email, name, avatar_url, provider, metadata, created_at, updated_at")
    .single();

  if (err || !data) return error("Update failed", 500);

  await dispatchWebhook(supabase, appId, "user.updated", { user_id: userId });
  return json(data);
}

async function handleChangePassword(
  req: Request,
  supabase: ReturnType<typeof createClient>,
  userId: string
): Promise<Response> {
  let body: { old_password?: string; new_password?: string };
  try { body = await req.json(); } catch { return error("Invalid JSON body"); }

  const { old_password, new_password } = body;
  if (!old_password || !new_password) {
    return error("old_password and new_password are required");
  }
  if (new_password.length < 8) return error("New password must be at least 8 characters");

  const { data: user } = await supabase
    .from("app_users")
    .select("password_hash")
    .eq("id", userId)
    .single();

  if (!user?.password_hash) return error("Password auth not available for this account", 400);

  const valid = await bcrypt.compare(old_password, user.password_hash);
  if (!valid) return error("Current password is incorrect", 401);

  const newHash = await bcrypt.hash(new_password);
  const { error: updateErr } = await supabase
    .from("app_users")
    .update({ password_hash: newHash, updated_at: new Date().toISOString() })
    .eq("id", userId);

  if (updateErr) return error("Failed to update password", 500);
  return json({ success: true });
}

async function handleDeleteMe(
  supabase: ReturnType<typeof createClient>,
  userId: string,
  appId: string
): Promise<Response> {
  const { data: user } = await supabase
    .from("app_users").select("email").eq("id", userId).single();

  const { error: deleteErr } = await supabase
    .from("app_users").delete().eq("id", userId);

  if (deleteErr) return error("Failed to delete account", 500);

  await dispatchWebhook(supabase, appId, "user.deleted", { user_id: userId, email: user?.email });
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// ── MAIN SERVE ────────────────────────────────────────────────────────────────

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const auth = await authenticate(req);
  if (!auth) return error("Unauthorized – valid Bearer token required", 401);

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/user-api\/?/, "").split("?")[0];

  try {
    if (path === "me") {
      if (req.method === "GET") return await handleGetMe(supabase, auth.userId);
      if (req.method === "PATCH") return await handlePatchMe(req, supabase, auth.userId, auth.appId);
      if (req.method === "DELETE") return await handleDeleteMe(supabase, auth.userId, auth.appId);
    }
    if (path === "change-password" && req.method === "POST") {
      return await handleChangePassword(req, supabase, auth.userId);
    }
    return error("Not found", 404);
  } catch (e) {
    console.error("Unhandled error:", e);
    return error("Internal server error", 500);
  }
});
