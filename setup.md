# AuthFlow Setup Guide

A complete setup guide for deploying AuthFlow — a multi-tenant authentication service built on Supabase.

---

## Prerequisites

- [Supabase CLI](https://supabase.com/docs/guides/cli) installed
- A Supabase project created at [supabase.com](https://supabase.com)
- Node.js 18+ (for local development)
- Deno 1.40+ (for edge functions)

---

## 1. Database Setup

Run the following SQL in your Supabase project's SQL editor (**Dashboard → SQL Editor → New query**).

### Schema DDL

```sql
-- Apps table: each record is a tenant application
CREATE TABLE apps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  publishable_key TEXT UNIQUE NOT NULL DEFAULT 'pk_' || encode(gen_random_bytes(24), 'hex'),
  secret_key TEXT UNIQUE NOT NULL DEFAULT 'sk_' || encode(gen_random_bytes(24), 'hex'),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- App end-users: isolated per app, not Supabase Auth users
CREATE TABLE app_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  password_hash TEXT,        -- bcrypt hash; NULL for OAuth-only users
  name TEXT,
  avatar_url TEXT,
  provider TEXT DEFAULT 'email',
  provider_id TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(app_id, email)
);

-- OAuth provider configuration per app
CREATE TABLE provider_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,    -- google, github, microsoft, x, linkedin, patreon, reddit, discord
  enabled BOOLEAN DEFAULT false,
  client_id TEXT,
  client_secret TEXT,        -- store encrypted in production (see section 5)
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(app_id, provider)
);

-- Allowed redirect URLs per app (whitelist for post-auth redirects)
CREATE TABLE redirect_urls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(app_id, url)
);

-- Webhooks per app
CREATE TABLE webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT encode(gen_random_bytes(32), 'hex'),
  events TEXT[] DEFAULT ARRAY['user.created', 'user.login'],
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Additional API keys beyond the app's default publishable/secret keys
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  publishable_key TEXT UNIQUE NOT NULL DEFAULT 'pk_' || encode(gen_random_bytes(24), 'hex'),
  created_at TIMESTAMPTZ DEFAULT now(),
  last_used_at TIMESTAMPTZ
);
```

### Indexes

```sql
CREATE INDEX idx_apps_owner_id ON apps(owner_id);
CREATE INDEX idx_app_users_app_id ON app_users(app_id);
CREATE INDEX idx_app_users_email ON app_users(app_id, email);
CREATE INDEX idx_provider_configs_app_id ON provider_configs(app_id);
CREATE INDEX idx_redirect_urls_app_id ON redirect_urls(app_id);
CREATE INDEX idx_webhooks_app_id ON webhooks(app_id);
CREATE INDEX idx_api_keys_app_id ON api_keys(app_id);
```

---

## 2. Row Level Security (RLS) Policies

Enable RLS on all tables and add these policies:

```sql
-- Enable RLS
ALTER TABLE apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE redirect_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- ── apps ──────────────────────────────────────────────────────────────
-- Platform users can only see and manage their own apps
CREATE POLICY "apps_select_own" ON apps
  FOR SELECT USING (auth.uid() = owner_id);

CREATE POLICY "apps_insert_own" ON apps
  FOR INSERT WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "apps_update_own" ON apps
  FOR UPDATE USING (auth.uid() = owner_id);

CREATE POLICY "apps_delete_own" ON apps
  FOR DELETE USING (auth.uid() = owner_id);

-- ── app_users ─────────────────────────────────────────────────────────
-- App end-users are managed only by the app owner (via service role in edge functions)
-- Dashboard queries are scoped to apps the owner controls
CREATE POLICY "app_users_select_app_owner" ON app_users
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM apps WHERE apps.id = app_users.app_id AND apps.owner_id = auth.uid())
  );

CREATE POLICY "app_users_delete_app_owner" ON app_users
  FOR DELETE USING (
    EXISTS (SELECT 1 FROM apps WHERE apps.id = app_users.app_id AND apps.owner_id = auth.uid())
  );

-- ── provider_configs ──────────────────────────────────────────────────
CREATE POLICY "provider_configs_all_app_owner" ON provider_configs
  FOR ALL USING (
    EXISTS (SELECT 1 FROM apps WHERE apps.id = provider_configs.app_id AND apps.owner_id = auth.uid())
  );

-- ── redirect_urls ─────────────────────────────────────────────────────
CREATE POLICY "redirect_urls_all_app_owner" ON redirect_urls
  FOR ALL USING (
    EXISTS (SELECT 1 FROM apps WHERE apps.id = redirect_urls.app_id AND apps.owner_id = auth.uid())
  );

-- ── webhooks ──────────────────────────────────────────────────────────
CREATE POLICY "webhooks_all_app_owner" ON webhooks
  FOR ALL USING (
    EXISTS (SELECT 1 FROM apps WHERE apps.id = webhooks.app_id AND apps.owner_id = auth.uid())
  );

-- ── api_keys ──────────────────────────────────────────────────────────
CREATE POLICY "api_keys_all_app_owner" ON api_keys
  FOR ALL USING (
    EXISTS (SELECT 1 FROM apps WHERE apps.id = api_keys.app_id AND apps.owner_id = auth.uid())
  );
```

---

## 3. Environment Variables

Set these secrets in your Supabase project (**Dashboard → Edge Functions → Manage secrets**, or via CLI):

```bash
# Required for all edge functions
supabase secrets set JWT_SECRET="your-very-long-random-secret-min-32-chars"

# These are automatically available in edge functions:
# SUPABASE_URL          – your project URL
# SUPABASE_SERVICE_ROLE_KEY – service role key (auto-injected by Supabase)
```

Generate a strong JWT secret:
```bash
openssl rand -base64 48
```

> ⚠️ **Never expose `JWT_SECRET` or `SUPABASE_SERVICE_ROLE_KEY` to the client.**

---

## 4. Deploy Edge Functions

```bash
# Login to Supabase CLI
supabase login

# Link to your project
supabase link --project-ref lqkpxervwakucksrnoss

# Deploy all edge functions
supabase functions deploy auth-handler
supabase functions deploy auth-config
supabase functions deploy user-api
supabase functions deploy webhook-handler

# Or deploy all at once
supabase functions deploy
```

Verify deployment:
```bash
supabase functions list
```

---

## 5. OAuth Provider Setup

For each OAuth provider you want to support, create an OAuth application and obtain a **Client ID** and **Client Secret**.

The redirect URI to register with each provider is:
```
https://lqkpxervwakucksrnoss.supabase.co/v1/auth/?key=YOUR_PUBLISHABLE_KEY
```

Or, if self-hosting the auth page:
```
https://your-domain.com/v1/auth/
```

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable **Google+ API** or **Google Identity API**
4. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
5. Application type: **Web application**
6. Add your redirect URI
7. Copy **Client ID** and **Client Secret** into AuthFlow dashboard

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Fill in **Homepage URL** and **Authorization callback URL** (your redirect URI)
4. Copy **Client ID** and generate a **Client Secret**

### Microsoft (Azure AD)

1. Go to [Azure Portal → App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps)
2. Click **New registration**
3. Set **Redirect URI** (Web platform)
4. Under **Certificates & secrets**, create a new **Client secret**
5. Copy **Application (client) ID** and the secret value

### X (Twitter)

1. Go to [Twitter Developer Portal](https://developer.twitter.com/en/portal)
2. Create a new App, enable **OAuth 2.0**
3. Set **Callback URI** to your redirect URI
4. Enable **Read** permissions under **App permissions**
5. Copy **Client ID** and **Client Secret**

### LinkedIn

1. Go to [LinkedIn Developer Portal](https://www.linkedin.com/developers/)
2. Create a new app, select **Sign In with LinkedIn using OpenID Connect**
3. Add your redirect URL under **Auth** tab
4. Copy **Client ID** and **Client Secret**

### Patreon

1. Go to [Patreon Platform](https://www.patreon.com/portal/registration/register-clients)
2. Create a new client
3. Set **Redirect URIs**
4. Copy **Client ID** and **Client Secret**

### Reddit

1. Go to [Reddit App Preferences](https://www.reddit.com/prefs/apps)
2. Click **Create App**, type: **web app**
3. Set **redirect uri**
4. Copy **client id** (below app name) and **secret**

### Discord

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new Application
3. Go to **OAuth2** tab
4. Add your redirect URI
5. Copy **Client ID** and **Client Secret**

---

## 6. Supabase Project Configuration

### Enable Email Auth

Supabase Auth is used for **platform users** (AuthFlow dashboard users only — not your app's end-users).

1. Go to **Dashboard → Authentication → Providers**
2. Ensure **Email** is enabled
3. Configure **Email Templates** as desired

### CORS

Edge functions allow all origins by default (`Access-Control-Allow-Origin: *`). For production, restrict this by modifying the `CORS_HEADERS` in each edge function.

### Site URL

Set your site URL in **Dashboard → Authentication → URL Configuration**:
```
https://your-authflow-domain.com
```

---

## 7. Hosting the Frontend

The three HTML files can be hosted on any static host:

| File | Path | Description |
|------|------|-------------|
| `index.html` | `/` | AuthFlow dashboard |
| `v1/auth/index.html` | `/v1/auth/` | Authentication UI for your apps |
| `api/index.html` | `/api/` | API documentation |

### Deploying to Vercel

```bash
npm i -g vercel
vercel --prod
```

### Deploying to Netlify

```bash
npm i -g netlify-cli
netlify deploy --prod --dir .
```

### Deploying to GitHub Pages

```bash
git add .
git commit -m "deploy"
git push origin main
# Enable Pages in repo settings → branch: main, folder: /
```

---

## 8. Integrating AuthFlow into Your App

### Step 1 – Create an app in the dashboard

Log in at your AuthFlow domain, click **+ New App**, and note the **Publishable Key**.

### Step 2 – Add a redirect URL

In **Providers** tab, add your app's callback URL (e.g., `https://myapp.com/auth/callback`).

### Step 3 – Redirect users to AuthFlow

```javascript
const loginUrl = new URL('https://your-authflow-domain.com/v1/auth/');
loginUrl.searchParams.set('key', 'pk_YOUR_PUBLISHABLE_KEY');
loginUrl.searchParams.set('redirect_uri', 'https://myapp.com/auth/callback');
loginUrl.searchParams.set('state', generateCsrfToken()); // optional CSRF protection

window.location.href = loginUrl.toString();
```

### Step 4 – Handle the callback

```javascript
// At https://myapp.com/auth/callback
const params = new URLSearchParams(window.location.search);
const token = params.get('token');
const state = params.get('state');

// Verify CSRF state
if (state !== getStoredCsrfToken()) {
  throw new Error('CSRF validation failed');
}

// Store the token
localStorage.setItem('authflow_token', token);

// Fetch user profile
const res = await fetch('https://lqkpxervwakucksrnoss.supabase.co/functions/v1/user-api/me', {
  headers: { Authorization: `Bearer ${token}` }
});
const user = await res.json();
console.log('Logged in as:', user.email);
```

### Step 5 – Verify the token server-side (optional)

```javascript
// Node.js example using jose
import { jwtVerify } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET);
const { payload } = await jwtVerify(token, secret);
console.log('User ID:', payload.sub);
console.log('App ID:', payload.app_id);
```

---

## 9. Webhook Configuration

Webhooks fire for these events:

| Event | Trigger |
|-------|---------|
| `user.created` | New user signs up |
| `user.login` | User signs in |
| `user.updated` | User profile updated |
| `user.deleted` | User account deleted |

### Payload Format

```json
{
  "event": "user.created",
  "timestamp": "2024-01-15T12:00:00.000Z",
  "payload": {
    "user_id": "uuid",
    "email": "user@example.com",
    "provider": "google"
  }
}
```

### Verifying Webhook Signatures

```javascript
const crypto = require('crypto');

function verifyWebhook(body, signature, secret) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return `sha256=${expected}` === signature;
}

// Express example
app.post('/webhooks/auth', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['x-authflow-signature'];
  if (!verifyWebhook(req.body, sig, process.env.WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  const { event, payload } = JSON.parse(req.body);
  console.log('Event:', event, payload);
  res.sendStatus(200);
});
```

---

## 10. Security Checklist

- [ ] `JWT_SECRET` is at least 32 random characters and stored as a Supabase secret
- [ ] `SUPABASE_SERVICE_ROLE_KEY` is never exposed to the browser
- [ ] RLS policies are enabled on all tables
- [ ] Redirect URLs are restricted to known domains in the dashboard
- [ ] OAuth client secrets are stored in AuthFlow (server-side only, never sent to browser)
- [ ] Webhook endpoints verify the `X-AuthFlow-Signature` header
- [ ] HTTPS is enforced for all redirect URIs
- [ ] JWT expiry is configured appropriately (default: 7 days)
