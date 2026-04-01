import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
import { create, verify, getNumericDate } from "https://deno.land/x/djwt@v2.8/mod.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const JWT_SECRET = Deno.env.get("JWT_SECRET")!;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, apikey",
};

function corsResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

function errorResponse(message: string, status = 400): Response {
  return corsResponse({ error: message }, status);
}

async function getCryptoKey(): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(JWT_SECRET);
  return await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function issueJWT(payload: Record<string, unknown>): Promise<string> {
  const key = await getCryptoKey();
  return await create(
    { alg: "HS256", typ: "JWT" },
    { ...payload, iat: getNumericDate(0), exp: getNumericDate(60 * 60 * 24 * 7) },
    key
  );
}

async function verifyJWT(token: string): Promise<Record<string, unknown>> {
  const key = await getCryptoKey();
  return await verify(token, key) as Record<string, unknown>;
}

async function getAppByPublishableKey(
  supabase: ReturnType<typeof createClient>,
  appKey: string
): Promise<{ id: string; name: string } | null> {
  const { data, error } = await supabase
    .from("apps")
    .select("id, name")
    .eq("publishable_key", appKey)
    .single();
  if (error || !data) return null;
  return data;
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

  if (!webhooks || webhooks.length === 0) return;

  for (const webhook of webhooks) {
    const body = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
    const signature = await hmacSign(webhook.secret, body);
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
      } catch (_) {
        // retry
      }
      attempts++;
      if (attempts < 3) await new Promise((r) => setTimeout(r, 1000 * attempts));
    }
  }
}

async function hmacSign(secret: string, body: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── ROUTE HANDLERS ────────────────────────────────────────────────────────────

async function handleSignup(req: Request, supabase: ReturnType<typeof createClient>): Promise<Response> {
  let body: { email?: string; password?: string; app_key?: string; name?: string };
  try { body = await req.json(); } catch { return errorResponse("Invalid JSON body"); }

  const { email, password, app_key, name } = body;
  if (!email || !password || !app_key) {
    return errorResponse("email, password, and app_key are required");
  }
  if (password.length < 8) return errorResponse("Password must be at least 8 characters");

  const app = await getAppByPublishableKey(supabase, app_key);
  if (!app) return errorResponse("Invalid publishable key", 401);

  const { data: existing } = await supabase
    .from("app_users")
    .select("id")
    .eq("app_id", app.id)
    .eq("email", email)
    .single();

  if (existing) return errorResponse("Email already in use", 409);

  const passwordHash = await bcrypt.hash(password);

  const { data: user, error } = await supabase
    .from("app_users")
    .insert({ app_id: app.id, email, password_hash: passwordHash, name: name || null, provider: "email" })
    .select("id, email, name, avatar_url, provider, created_at")
    .single();

  if (error || !user) return errorResponse("Failed to create user: " + (error?.message || "unknown"), 500);

  const token = await issueJWT({ sub: user.id, email: user.email, app_id: app.id });

  await dispatchWebhook(supabase, app.id, "user.created", { user_id: user.id, email: user.email, provider: "email" });

  return corsResponse({ token, user });
}

async function handleSignin(req: Request, supabase: ReturnType<typeof createClient>): Promise<Response> {
  let body: { email?: string; password?: string; app_key?: string };
  try { body = await req.json(); } catch { return errorResponse("Invalid JSON body"); }

  const { email, password, app_key } = body;
  if (!email || !password || !app_key) {
    return errorResponse("email, password, and app_key are required");
  }

  const app = await getAppByPublishableKey(supabase, app_key);
  if (!app) return errorResponse("Invalid publishable key", 401);

  const { data: user } = await supabase
    .from("app_users")
    .select("id, email, name, avatar_url, provider, password_hash, created_at")
    .eq("app_id", app.id)
    .eq("email", email)
    .single();

  if (!user || !user.password_hash) return errorResponse("Invalid credentials", 401);

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return errorResponse("Invalid credentials", 401);

  const token = await issueJWT({ sub: user.id, email: user.email, app_id: app.id });

  await dispatchWebhook(supabase, app.id, "user.login", { user_id: user.id, email: user.email, provider: "email" });

  const { password_hash: _, ...safeUser } = user;
  return corsResponse({ token, user: safeUser });
}

async function handleOAuthCallback(req: Request, supabase: ReturnType<typeof createClient>): Promise<Response> {
  let body: { provider?: string; code?: string; redirect_uri?: string; app_key?: string };
  try { body = await req.json(); } catch { return errorResponse("Invalid JSON body"); }

  const { provider, code, redirect_uri, app_key } = body;
  if (!provider || !code || !redirect_uri || !app_key) {
    return errorResponse("provider, code, redirect_uri, and app_key are required");
  }

  const app = await getAppByPublishableKey(supabase, app_key);
  if (!app) return errorResponse("Invalid publishable key", 401);

  const { data: providerCfg } = await supabase
    .from("provider_configs")
    .select("client_id, client_secret")
    .eq("app_id", app.id)
    .eq("provider", provider)
    .eq("enabled", true)
    .single();

  if (!providerCfg?.client_id || !providerCfg?.client_secret) {
    return errorResponse("Provider not configured", 400);
  }

  const OAUTH_TOKEN_URLS: Record<string, string> = {
    google: "https://oauth2.googleapis.com/token",
    github: "https://github.com/login/oauth/access_token",
    microsoft: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    x: "https://api.twitter.com/2/oauth2/token",
    linkedin: "https://www.linkedin.com/oauth/v2/accessToken",
    patreon: "https://www.patreon.com/api/oauth2/token",
    reddit: "https://www.reddit.com/api/v1/access_token",
    discord: "https://discord.com/api/oauth2/token",
  };

  const OAUTH_USER_URLS: Record<string, string> = {
    google: "https://www.googleapis.com/oauth2/v3/userinfo",
    github: "https://api.github.com/user",
    microsoft: "https://graph.microsoft.com/v1.0/me",
    x: "https://api.twitter.com/2/users/me?user.fields=name,profile_image_url",
    linkedin: "https://api.linkedin.com/v2/me",
    patreon: "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url",
    reddit: "https://oauth.reddit.com/api/v1/me",
    discord: "https://discord.com/api/users/@me",
  };

  const tokenUrl = OAUTH_TOKEN_URLS[provider];
  if (!tokenUrl) return errorResponse("Unsupported provider", 400);

  // Exchange code for access token
  const tokenParams = new URLSearchParams({
    client_id: providerCfg.client_id,
    client_secret: providerCfg.client_secret,
    code,
    redirect_uri,
    grant_type: "authorization_code",
  });

  const tokenRes = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: tokenParams.toString(),
  });

  let tokenData: { access_token?: string; error?: string };
  const tokenText = await tokenRes.text();
  try {
    tokenData = JSON.parse(tokenText);
  } catch {
    const p = new URLSearchParams(tokenText);
    tokenData = { access_token: p.get("access_token") || undefined };
  }

  if (!tokenData.access_token) {
    return errorResponse("Failed to get access token: " + (tokenData.error || tokenText), 400);
  }

  // Fetch user profile
  const userUrl = OAUTH_USER_URLS[provider];
  const profileRes = await fetch(userUrl, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const profile = await profileRes.json();

  // Normalize profile across providers
  let oauthEmail: string | null = null;
  let oauthName: string | null = null;
  let oauthAvatarUrl: string | null = null;
  let oauthId: string | null = null;

  switch (provider) {
    case "google":
      oauthEmail = profile.email;
      oauthName = profile.name;
      oauthAvatarUrl = profile.picture;
      oauthId = profile.sub;
      break;
    case "github":
      oauthEmail = profile.email;
      oauthName = profile.name || profile.login;
      oauthAvatarUrl = profile.avatar_url;
      oauthId = String(profile.id);
      // Fetch email separately if not present
      if (!oauthEmail) {
        const emailRes = await fetch("https://api.github.com/user/emails", {
          headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        const emails = await emailRes.json();
        const primary = emails.find((e: { primary: boolean; email: string }) => e.primary);
        oauthEmail = primary?.email || null;
      }
      break;
    case "microsoft":
      oauthEmail = profile.mail || profile.userPrincipalName;
      oauthName = profile.displayName;
      oauthId = profile.id;
      break;
    case "x":
      oauthName = profile.data?.name;
      oauthId = profile.data?.id;
      oauthAvatarUrl = profile.data?.profile_image_url;
      break;
    case "linkedin":
      oauthName = `${profile.localizedFirstName || ""} ${profile.localizedLastName || ""}`.trim();
      oauthId = profile.id;
      break;
    case "patreon":
      oauthEmail = profile.data?.attributes?.email;
      oauthName = profile.data?.attributes?.full_name;
      oauthAvatarUrl = profile.data?.attributes?.image_url;
      oauthId = profile.data?.id;
      break;
    case "reddit":
      oauthName = profile.name;
      oauthId = profile.id;
      oauthAvatarUrl = profile.icon_img;
      break;
    case "discord":
      oauthEmail = profile.email;
      oauthName = profile.global_name || profile.username;
      oauthAvatarUrl = profile.avatar
        ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
        : null;
      oauthId = profile.id;
      break;
  }

  if (!oauthEmail && !oauthId) {
    return errorResponse("Could not obtain user identity from provider", 400);
  }

  // Upsert user
  const lookupEmail = oauthEmail || `${provider}_${oauthId}@oauth.authflow.internal`;

  const { data: existingUser } = await supabase
    .from("app_users")
    .select("id, email")
    .eq("app_id", app.id)
    .eq("email", lookupEmail)
    .single();

  let userId: string;
  let isNew = false;

  if (existingUser) {
    userId = existingUser.id;
    await supabase.from("app_users").update({
      name: oauthName,
      avatar_url: oauthAvatarUrl,
      provider,
      provider_id: oauthId,
      updated_at: new Date().toISOString(),
    }).eq("id", userId);
  } else {
    const { data: newUser, error } = await supabase
      .from("app_users")
      .insert({
        app_id: app.id,
        email: lookupEmail,
        name: oauthName,
        avatar_url: oauthAvatarUrl,
        provider,
        provider_id: oauthId,
      })
      .select("id")
      .single();
    if (error || !newUser) return errorResponse("Failed to create user", 500);
    userId = newUser.id;
    isNew = true;
  }

  const token = await issueJWT({ sub: userId, email: lookupEmail, app_id: app.id });

  await dispatchWebhook(supabase, app.id, isNew ? "user.created" : "user.login", {
    user_id: userId,
    email: lookupEmail,
    provider,
  });

  return corsResponse({ token, user: { id: userId, email: lookupEmail, name: oauthName, provider } });
}

async function handleVerify(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const token = url.searchParams.get("token");
  if (!token) return errorResponse("token parameter required");

  try {
    const payload = await verifyJWT(token);
    return corsResponse({ valid: true, payload });
  } catch (e) {
    return corsResponse({ valid: false, error: (e as Error).message }, 401);
  }
}

// ── MAIN SERVE ────────────────────────────────────────────────────────────────

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/auth-handler\/?/, "").split("?")[0];

  try {
    if (req.method === "POST" && path === "signup") return await handleSignup(req, supabase);
    if (req.method === "POST" && path === "signin") return await handleSignin(req, supabase);
    if (req.method === "POST" && path === "oauth-callback") return await handleOAuthCallback(req, supabase);
    if (req.method === "GET" && path === "verify") return await handleVerify(req);

    return errorResponse("Not found", 404);
  } catch (e) {
    console.error("Unhandled error:", e);
    return errorResponse("Internal server error", 500);
  }
});
