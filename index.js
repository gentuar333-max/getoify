const express = require('express');
const crypto = require('crypto');
const dotenv = require('dotenv');
const axios = require('axios');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

dotenv.config({ override: false });

const app = express();

// Ruaj raw bytes te req.rawBody para parsing — i vetmi menyrim i besueshëm
// per HMAC verification te Shopify webhooks. express.raw() dhe express.json()
// ne paralel shkaktojne konflikt: nje prej tyre merr streamin, tjetri merr
// objekt JSON. JSON.stringify(object) nuk prodhon bytes identike me payload-in
// origjinal (whitespace, key order) → HMAC deshton gjithmone.
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));
app.use(express.static(path.join(__dirname, 'public')));

const { 
  SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_SCOPES, 
  APP_URL, SUPABASE_URL, SUPABASE_SERVICE_KEY
} = process.env;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ─── SHOP SESSION AUTH ────────────────────────────────────────────────────
// Zëvendëson "shop=X ne URL" si identitet. Pas OAuth-it te suksesshem
// (/auth/callback), lëshohet nje cookie e nënshkruar (HttpOnly, e
// pafalsifikueshme pa SHOPIFY_API_SECRET) qe deshmon se ky browser ka
// kaluar vertet OAuth-in per ate shop. Route-t e ndjeshme (te dhena/veprime
// per nje shop specifik) kerkojne kete cookie permes requireShopAuth, dhe
// perdorin req.verifiedShop — jo me req.query.shop apo req.body.shop, qe
// deri tani ishin te falsifikueshme nga kushdo qe di emrin e shop-it.
const SESSION_COOKIE_NAME = 'getoify_session';
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 dite

function toBase64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromBase64Url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function signSession(shop) {
  const payload = toBase64Url(Buffer.from(JSON.stringify({ shop, iat: Date.now() })));
  const sig = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(cookieValue) {
  if (!cookieValue) return null;
  const dotIdx = cookieValue.lastIndexOf('.');
  if (dotIdx === -1) return null;
  const payload = cookieValue.slice(0, dotIdx);
  const sig = cookieValue.slice(dotIdx + 1);
  const expectedSig = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(payload).digest('hex');
  const sigBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    const data = JSON.parse(fromBase64Url(payload).toString('utf8'));
    if (!data.shop || !data.iat) return null;
    if (Date.now() - data.iat > SESSION_MAX_AGE_MS) return null;
    return data.shop;
  } catch (e) {
    return null;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}

// Kerkohet ne cdo route qe lexon/shkruan te dhena te nje shop specifik.
// Verifikon cookie-n e sesionit dhe vendos req.verifiedShop — handler-at
// duhet ta perdorin kete, jo me req.query.shop apo req.body.shop.
function requireShopAuth(req, res, next) {
  const shop = verifySession(getCookie(req, SESSION_COOKIE_NAME));
  if (!shop) return res.status(401).json({ error: 'Not authenticated. Please reconnect your store.' });
  req.verifiedShop = shop;
  next();
}

// Version me i bute i requireShopAuth — per route qe kthejne te dhena me pak
// sensitive (katalog produktesh, status i pergjithshem — jo access_token apo
// veprime qe ndryshojne plan/te dhena). Provon cookie-n e sesionit e para
// (e preferuar, e njejta siguri sa requireShopAuth); nese mungon, pranon
// `shop` nga query VETEM nese eshte dyqan REAL i instaluar tashmë ne
// Supabase — jo çdo string i shpikur. Kjo ekziston sepse review-i i Shopify
// App Store konfirmuar s'e mban gjithmone cookie sesioni gjate testimit
// (shih gjetjen per "Sync from Shopify" — 2.1.4), dhe /products, /status
// s'jane aq sensitive sa te justifikojne rrezikun e nje refuzimi tjeter.
async function requireShopAuthOrKnownShop(req, res, next) {
  const cookieShop = verifySession(getCookie(req, SESSION_COOKIE_NAME));
  if (cookieShop) {
    req.verifiedShop = cookieShop;
    return next();
  }
  const queryShop = req.query.shop;
  if (queryShop && isValidShopDomain(queryShop)) {
    try {
      const { data } = await supabase.from('stores').select('shop').eq('shop', queryShop).maybeSingle();
      if (data) {
        console.warn(`[soft-auth] ${queryShop} — pa cookie sesioni, por dyqan real i instaluar, lejohet (${req.path})`);
        req.verifiedShop = queryShop;
        return next();
      }
    } catch(e) {
      console.warn('[soft-auth] Kontrolli i dyqanit deshtoi:', e.message);
    }
  }
  return res.status(401).json({ error: 'Not authenticated. Please reconnect your store.' });
}

// Per endpoint-et e mirembajtjes (jo per merchant, per ty si zhvillues) —
// kerkon ADMIN_API_KEY (query ?admin_key= ose header x-admin-key) ne vend
// te session cookie-t, sepse keto s'kalojne nga dashboard-i i merchant-it.
// Nese ADMIN_API_KEY s'eshte vendosur ne env, route-t bllokohen (fail-closed).
function requireAdminKey(req, res, next) {
  const expected = process.env.ADMIN_API_KEY;
  if (!expected) {
    console.warn('[admin-key] ADMIN_API_KEY nuk eshte vendosur — route i mirembajtjes bllokohet per siguri');
    return res.status(503).json({ error: 'Admin routes are not configured' });
  }
  const provided = String(req.query.admin_key || req.headers['x-admin-key'] || '');
  const providedBuf = Buffer.from(provided);
  const expectedBuf = Buffer.from(expected);
  if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── OAUTH CALLBACK HARDENING ─────────────────────────────────────────────
// Format i vlefshem per domain shop-i, sipas rregullit qe vete Shopify e
// dokumenton: vetem shkronja a-z, numra 0-9, pika dhe viza, dhe DUHET te
// mbaroje me ".myshopify.com". Perdoret PARA se `shop` te futet ne çdo URL
// te jashtme (/auth, /auth/callback) — mbyll rrugen e SSRF-it ku dikush do
// te vendoste nje host arbitrar (p.sh. "shop=intern.local") dhe do e bente
// serverin tone te dergonte kerkesa (bashke me client_secret-in tone!) atje.
function isValidShopDomain(shop) {
  return typeof shop === 'string' && /^[a-zA-Z0-9.-]+\.myshopify\.com$/.test(shop);
}

// Verifikon hmac-un qe Shopify e shton te query string i /auth/callback —
// KY eshte ndryshe nga HMAC i webhook-ve (verifyShopifyWebhookHmac me poshte):
// per OAuth callback, Shopify e nenshkruan STRING-un e parametrave (jo trupin
// e kerkeses), dhe rezultati eshte HEX (jo base64). Sipas shopify.dev:
// hiq 'hmac' (dhe 'signature' nese ekziston), rradhit çelesat e mbetur
// leksikografikisht, bashko si "kyc=vlere" me '&', HMAC-SHA256 me client
// secret, krahaso hex digest-in me parametrin hmac.
function verifyOAuthCallbackHmac(query) {
  const { hmac, signature, ...rest } = query;
  if (!hmac || typeof hmac !== 'string') return false;
  const message = Object.keys(rest).sort().map(key => `${key}=${rest[key]}`).join('&');
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(message).digest('hex');
  const digestBuf = Buffer.from(digest, 'utf8');
  const hmacBuf = Buffer.from(hmac, 'utf8');
  if (digestBuf.length !== hmacBuf.length) return false;
  return crypto.timingSafeEqual(digestBuf, hmacBuf);
}

// Intercept Shopify 401 — mark token invalid in Supabase
axios.interceptors.response.use(
  res => res,
  async err => {
    const url = err.config?.url || '';
    const status = err.response?.status;

    // 429 nga Shopify — i mundshem tani me konkurrence ne bulk-localize-all
    // (disa produkte njekohesisht = me shume kerkesa/sekonde te i njejti shop).
    // Rites NJE here me Retry-After (ose 2s fallback), max 3 perpjekje gjithsej.
    if (status === 429 && url.includes('myshopify.com')) {
      const cfg = err.config;
      cfg.__retryCount = (cfg.__retryCount || 0) + 1;
      if (cfg.__retryCount <= 3) {
        const retryAfter = parseFloat(err.response.headers?.['retry-after']) || 2;
        console.warn(`[429] Shopify rate limit — riprovo ${url} pas ${retryAfter}s (perpjekja ${cfg.__retryCount}/3)`);
        await new Promise(r => setTimeout(r, retryAfter * 1000));
        return axios(cfg);
      }
      console.error(`[429] Shopify rate limit — u dorezuar pas 3 perpjekjeve: ${url}`);
    }

    if (status === 401 && url.includes('myshopify.com')) {
      const shopMatch = url.match(/https:\/\/([^/]+)/);
      if (shopMatch) {
        const shop = shopMatch[1];
        console.warn(`[401] Token invalid for ${shop} — marking in Supabase`);
        await supabase.from('stores').update({ token_invalid: true }).eq('shop', shop);
      }
    }
    if (status !== 401 && url.includes('myshopify.com/admin/oauth/access_token')) {
      const shopMatch = url.match(/https:\/\/([^/]+)/);
      if (shopMatch) {
        await supabase.from('stores').update({ token_invalid: false }).eq('shop', shopMatch[1]);
      }
    }
    return Promise.reject(err);
  }
);

const { normalizeProductId } = require('./lib/product-id');
const { fetchAllRows } = require('./lib/supabase-pagination');
const { localizeCollection, bulkLocalizeCollections } = require('./lib/localize-collection');
const { localizeArticle, bulkLocalizeBlogs } = require('./lib/localize-blog');
// Stripe dhe lib/shopify-billing.js u hoqen — kishin /checkout dhe /billing/callback
// te vet qe konfliktonin (Express perdor handler-in e PARE te regjistruar per
// te njejtin path) me /checkout dhe /billing/callback e ndertuara me poshte ne
// kete file. Stripe ishte registruar I PARI dhe interceptonte CDO kerkese
// /checkout, duke ridrejtuar merchant te checkout.stripe.com — kjo eshte
// shkaku i sakte i refuzimit nga Shopify (1.2.1 off-platform billing).
// Tani /checkout dhe /billing/callback me poshte jane TE VETMET handlers.

// ─── WIDGET SCRIPTTAG ─────────────────────────────────────────────────────

async function installScriptTag(shop, token) {
  const scriptUrl = `${APP_URL}/widget.js`;
  try {
    const existing = await axios.get(
      `https://${shop}/admin/api/2026-07/script_tags.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const alreadyInstalled = (existing.data.script_tags || []).some(s => s.src === scriptUrl);
    if (alreadyInstalled) { console.log(`[widget] ScriptTag already installed: ${shop}`); return; }
    await axios.post(
      `https://${shop}/admin/api/2026-07/script_tags.json`,
      { script_tag: { event: 'onload', src: scriptUrl } },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
    );
    console.log(`[widget] ScriptTag installed: ${shop}`);
  } catch(e) {
    console.error(`[widget] Install failed: ${shop}`, e.response?.data || e.message);
  }
}

async function removeScriptTag(shop, token) {
  const scriptUrl = `${APP_URL}/widget.js`;
  try {
    const existing = await axios.get(
      `https://${shop}/admin/api/2026-07/script_tags.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    for (const tag of (existing.data.script_tags || [])) {
      if (tag.src === scriptUrl) {
        await axios.delete(
          `https://${shop}/admin/api/2026-07/script_tags/${tag.id}.json`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        console.log(`[widget] ScriptTag removed: ${shop}`);
      }
    }
  } catch(e) {
    console.error(`[widget] Remove failed: ${shop}`, e.response?.data || e.message);
  }
}

// Install widget manually — thirre nje here per stores ekzistuese
// https://getoify.com/install-widget-manual?shop=xxx
app.get('/install-widget-manual', requireAdminKey, async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  try {
    const { data: store } = await supabase
      .from('stores')
      .select('access_token')
      .eq('shop', shop)
      .single();
    if (!store?.access_token) return res.status(404).json({ error: 'Store not found' });
    await installScriptTag(shop, store.access_token);
    res.json({ success: true, shop, message: 'Widget installed' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Migrim ScriptTag -> Theme App Extension: hiq ScriptTag-un e vjeter per nje
// shop qe e kishte instaluar para migrimit. Thirre NJE HERE per çdo shop
// ekzistues, PASI merchant-i te kete aktivizuar app embed block-un e ri ne
// Theme Editor — perndryshe do te shihte widget-in DYFISH (te vjetrin +
// te riun) derisa te fshihet ky ScriptTag.
// https://getoify.com/remove-widget-scripttag?shop=xxx&admin_key=...
app.get('/remove-widget-scripttag', requireAdminKey, async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  try {
    const { data: store } = await supabase
      .from('stores')
      .select('access_token')
      .eq('shop', shop)
      .single();
    if (!store?.access_token) return res.status(404).json({ error: 'Store not found' });
    await removeScriptTag(shop, store.access_token);
    res.json({ success: true, shop, message: 'Old ScriptTag removed (if it existed)' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Widget config endpoint — widget.js e thirr kete per te marre gjuhet aktive
app.get('/widget-config', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  res.header('Access-Control-Allow-Origin', '*');
  try {
    const { data } = await supabase
      .from('stores')
      .select('selected_locales')
      .eq('shop', shop)
      .single();
    const locales = data?.selected_locales || [];
    res.json({ shop, locales });
  } catch(e) {
    res.json({ shop, locales: [] });
  }
});

const SHOPIFY_PRODUCTS_PAGE = 250;
const SHOPIFY_PRODUCTS_TIMEOUT_MS = 60000;

// Planete e Getoify — product_limit eshte numri max i produkteve unike
// qe mund te lokalizohen gjate periudhes se planit. Perdoret nga te gjitha
// endpoint-et per te bllokuar tejkalimin e limitit. DUHET te jete ketu
// (globale) sepse app.locals.PLANS lexohet nga disa endpoint — ne te kaluaren
// kurrë nuk u caktua, prandaj if (PLANS) ishte gjithmone false dhe limitet
// nuk funksiononin fare.
// Gjuhet e suportuara nga Getoify — merchant zgjedh nga keto
const SUPPORTED_LOCALES = {
  // Europë Perëndimore (tregjet kryesore)
  'en': 'English',
  'fr': 'French',
  'de': 'German',
  'it': 'Italian',
  'es': 'Spanish',
  'nl': 'Dutch',
  'pt-BR': 'Portuguese (Brazil)',
  'pt-PT': 'Portuguese (Portugal)',
  'pl': 'Polish',
  // Skandinavia (ecommerce i fortë)
  'sv': 'Swedish',
  'da': 'Danish',
  'nb': 'Norwegian',
  // Europë Lindore (në rritje)
  'cs': 'Czech',
  'ro': 'Romanian',
  'hu': 'Hungarian',
  // Tregje të mëdha globale
  'ar': 'Arabic',
  'ja': 'Japanese',
  'ko': 'Korean',
  'tr': 'Turkish',
  'id': 'Indonesian',
};

const PLANS = {
  free:        { label: 'Free',       product_limit: 15,   bulk_limit: 15,   language_limit: 1  },
  description: { label: 'Local',      product_limit: 50,   bulk_limit: 50,   language_limit: 1  },
  starter:     { label: 'Starter',    product_limit: 125,  bulk_limit: 125,  language_limit: 2  },
  growth:      { label: 'Growth',     product_limit: 300,  bulk_limit: 300,  language_limit: 5  },
  pro:         { label: 'Pro',        product_limit: 700,  bulk_limit: 700,  language_limit: 10 },
  enterprise:  { label: 'Enterprise', product_limit: 1400, bulk_limit: 1400, language_limit: 20 },
};
app.locals.PLANS = PLANS;
app.locals.SUPPORTED_LOCALES = SUPPORTED_LOCALES;

// Funksioni ndihmës per COUNT(DISTINCT product_id) — perdor Supabase RPC
// per te shmangur problemin e limitit te rreshtave (default 1000, max 10000).
// Me SQL DISTINCT, kjo eshte me e sakt dhe me performante se deduplication
// ne JavaScript pas fetch-imit te mijera rreshtave.
async function getLocalizedProductCount(shop, planStartedAt) {
  try {
    const { data, error } = await supabase.rpc('get_localized_product_count', {
      p_shop: shop,
      p_started_at: planStartedAt || null
    });
    if (error) throw error;
    return typeof data === 'number' ? data : parseInt(data || '0', 10);
  } catch(e) {
    console.warn('[plan-count] RPC failed, fallback to query:', e.message);
    // Fallback: query me limit te larte
    let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(50000);
    if (planStartedAt) q = q.gte('created_at', planStartedAt);
    const { data: rows } = await q;
    return new Set((rows || []).map(r => String(r.product_id))).size;
  }
}


// Sa çifte (produkt, gjuhe) perpunohen njekohesisht — nga /poll per rradhen
// (shih processQueuedTranslations) dhe historikisht nga bulk-localize-all.
// SHENIM: qysh nga rradhitja e re me poshte, /bulk-localize-all VETEM
// vendos pune ne rradhe (status 'queued') dhe kthehet menjehere — konkurrenca
// aplikohet nga /poll kur i procesion, jo me brenda vete kerkeses HTTP.
const BULK_CONCURRENCY = 4;

// Prag: nese numri i çifteve (produkt, gjuhe) per t'u perkthyer eshte NEN
// kete kufi, procesohen MENJEHERE brenda vete kerkeses (pergjigje e plote,
// sjellje e vjeter — e shpejte per dyqane te vogla/mesatare). Vetem kur e
// KALON, vendosen ne rradhe (shih QUEUE_BATCH_SIZE me poshte). Bazuar te
// ~20 perkthime/minute me BULK_CONCURRENCY=4 (~10-15s secili) — rregullo
// sipas limitit real te timeout te planit tend Vercel.
const IMMEDIATE_BULK_THRESHOLD = 20;

// Sa çifte (produkt, gjuhe) 'queued' procesohen NE NJE THIRRJE te /poll.
// Mban çdo invokim brenda kohes se sigurt per Vercel (cron çdo 5 min),
// pavaresisht sa jane gjithsej ne rradhe — pjesa e mbetur vazhdon invokimin
// tjeter. Numri konkret varet nga limiti real i timeout-it te planit tend
// Vercel — 30 eshte nje fillim konservativ, i rregullueshem sipas asaj qe
// vezhgon ne praktike (logs: sa kohe zgjat nje invokim /poll).
const QUEUE_BATCH_SIZE = 30;

// Ekzekuton 'items' me konkurrence maksimale 'limit', pa varesi te jashtme.
// 'limit' "runner" lupa rrjedhin paralel, secila merr artikullin tjeter te
// lire sapo perfundon te vetin — nuk pret "batch"-in te plotesohet (me
// efikase se chunking i thjeshte ne grupe fikse).
async function runWithConcurrency(items, limit, worker) {
  let nextIndex = 0;
  async function runNext() {
    while (nextIndex < items.length) {
      const i = nextIndex++;
      await worker(items[i], i);
    }
  }
  const runners = Array.from({ length: Math.min(limit, items.length) }, () => runNext());
  await Promise.all(runners);
}

const LOCALE_MAP = {
  'en': 'English', 'fr': 'French', 'de': 'German', 'it': 'Italian',
  'es': 'Spanish', 'nl': 'Dutch', 'pt-PT': 'Portuguese', 'pt-BR': 'Brazilian Portuguese',
  'pt': 'Portuguese', 'pl': 'Polish', 'sv': 'Swedish', 'da': 'Danish',
  'nb': 'Norwegian', 'cs': 'Czech', 'ro': 'Romanian', 'hu': 'Hungarian',
  'ar': 'Arabic', 'ja': 'Japanese', 'ko': 'Korean', 'tr': 'Turkish',
  'id': 'Indonesian', 'fi': 'Finnish', 'zh': 'Chinese', 'hi': 'Hindi'
};

// Nxjerr domain-in e shop-it nga vlera e dekoduar e 'host' parametrit qe
// Shopify e dergon kur merchant klikon "Open app" nga App Store/Admin —
// formati varet nese eshte admin i vjeter (shop.myshopify.com/admin) apo
// i ri, i unifikuar (admin.shopify.com/store/handle). host vjen pa
// 'padding' (=) - e shtojme vete perpara se ta dekodojme per siguri
// maksimale ndaj çdo variacioni base64 decoder-i.
function extractShopFromHost(hostParam) {
  try {
    let padded = String(hostParam);
    while (padded.length % 4) padded += '=';
    const decoded = Buffer.from(padded, 'base64').toString('utf8');

    const oldFormat = decoded.match(/^([a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com)/);
    if (oldFormat) return oldFormat[1];

    const newFormat = decoded.match(/admin\.shopify\.com\/store\/([a-zA-Z0-9-]+)/);
    if (newFormat) return `${newFormat[1]}.myshopify.com`;

    return null;
  } catch (e) {
    return null;
  }
}

// Static pages
app.get('/', (req, res) => {
  // Nese Shopify e ka dërguar hmac+host (merchant klikoi "Open app" nga
  // App Store/Admin — Shopify e dergon kete PAVARESISHT nese app-i eshte
  // embedded apo jo), verifikojme dhe ridrejtojme direkt te OAuth, pa e
  // detyruar merchant-in te shkruaje manualisht domain-in qe Shopify
  // tashme e di. Perdor te njejtin verifikim HMAC si /auth/callback (i
  // njejti algoritem i Shopify per parametra query te nenshkruar) — nese
  // hmac s'perputhet ose host s'jep shop te vlefshem, bie normalisht te
  // faqja statike (rasti i vizitorit organik, pa parametra nga Shopify).
  if (req.query.hmac && req.query.host && verifyOAuthCallbackHmac(req.query)) {
    const shop = extractShopFromHost(req.query.host);
    if (shop && isValidShopDomain(shop)) {
      return res.redirect('/auth?shop=' + encodeURIComponent(shop));
    }
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/tone', (req, res) => res.sendFile(path.join(__dirname, 'public', 'tone.html')));
app.get('/glossary', (req, res) => res.sendFile(path.join(__dirname, 'public', 'glossary.html')));
app.get('/products-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'products.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'public', 'settings.html')));
app.get('/autosync', (req, res) => res.sendFile(path.join(__dirname, 'public', 'autosync.html')));
app.get('/product', (req, res) => res.sendFile(path.join(__dirname, 'public', 'product-detail.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
app.get('/language-switcher', (req, res) => res.sendFile(path.join(__dirname, 'public', 'language-switcher.html')));
app.get('/google6e865cb2268111cc.html', (req, res) => res.send('google-site-verification: google6e865cb2268111cc.html'));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

// ─── SHOPIFY BILLING API ─────────────────────────────────────────────────────
const PLAN_PRICES = {
  free:        { monthly: 0,   yearly: 0,   label: 'Free'       },
  description: { monthly: 9,   yearly: 8,   label: 'Local'      },
  starter:     { monthly: 19,  yearly: 15,  label: 'Starter'    },
  growth:      { monthly: 49,  yearly: 39,  label: 'Growth'     },
  pro:         { monthly: 99,  yearly: 79,  label: 'Pro'        },
  enterprise:  { monthly: 199, yearly: 159, label: 'Enterprise' },
};

// Funksion ndihmës per dergimin e email notifikimeve me Resend
// Thirret kur merchant paguan plan te ri ose arrin limitin
async function sendNotification(subject, html) {
  const apiKey = process.env.RESEND_API_KEY;
  const to = process.env.NOTIFY_EMAIL || 'contact@premiumartisan.fr';
  if (!apiKey) return; // Nese RESEND_API_KEY nuk eshte vendosur, kaperceje
  try {
    await axios.post('https://api.resend.com/emails', {
      from: 'Getoify <notifications@getoify.com>',
      to,
      subject,
      html
    }, { headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' } });
    console.log(`[notify] Email sent: ${subject}`);
  } catch(e) {
    console.warn('[notify] Email failed:', e.response?.data || e.message);
  }
}

// /plan — perdoret nga settings.html (loadPlan) per te shfaqur planin aktual.
// Zevendeson /plan e vjeter te lib/stripe.js — tani lexon direkt nga stores
// (plan, billing_cycle) qe perditesohen nga /billing/callback me poshte.
app.get('/plan', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  try {
    const { data: store } = await supabase
      .from('stores')
      .select('plan, billing_cycle, billing_id')
      .eq('shop', shop)
      .single();
    res.json({
      plan: store?.plan || 'free',
      billing_cycle: store?.billing_cycle || null,
      has_subscription: !!store?.billing_id
    });
  } catch(e) {
    res.json({ plan: 'free', billing_cycle: null, has_subscription: false });
  }
});

// Zbulon nese dyqani eshte development/test store i Shopify Partners —
// keto NUK mund te krijojne RecurringApplicationCharge me test:false, Shopify
// e refuzon. Shopify reviewer-at GJITHMONE testojne ne dev stores — kjo eshte
// shkaku i sakte i "billing failed when attempting to subscribe" te raportuar.
// Default i sigurt kur s'mund te percaktohet: test:true (ne kete faze pa
// klient pagues real, kjo eshte gjithmone zgjedhja e duhur — false negative
// (test:true ne dyqan real) thjesht s'mbledh para njehere, false positive
// (test:false ne dev store) e bllokon plotesisht flow-in e billing-ut).
async function isDevelopmentStore(shop, token) {
  try {
    const shopRes = await axios.get(
      `https://${shop}/admin/api/2026-07/shop.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const planName = (shopRes.data.shop?.plan_name || '').toLowerCase();
    const planDisplay = (shopRes.data.shop?.plan_display_name || '').toLowerCase();
    return planName.includes('partner_test') || planName.includes('dev') ||
      planName === 'staff_business' || planDisplay.includes('development') ||
      planDisplay.includes('partner');
  } catch(e) {
    console.warn('[billing] Could not determine store plan type, defaulting to test:true for safety:', e.message);
    return true;
  }
}

app.get('/checkout', async (req, res) => {
  const { plan, billing, shop } = req.query;
  // isValidShopDomain (jo requireShopAuth): kjo route s'bën gjë tjetër veç
  // ndërton URL dhe ridrejton te faqja e HOSTUAR nga vetë Shopify — Shopify
  // vetë e kontrollon aksesin atje (kërkon login si admin i asaj dyqani),
  // pra requireShopAuth këtu s'shton mbrojtje reale, vetëm rrezik: nëse
  // Shopify e teston këtë route review-in pa cookie sesioni (proces
  // automatik review-i), do të merrte 401 në vend të ridrejtimit — pikërisht
  // simptoma "billing failed when attempting to subscribe" e raportuar.
  if (!plan || !shop || !isValidShopDomain(shop)) return res.status(400).send('Missing or invalid plan/shop');
  let store;
  try {
    store = await getStore(shop);
  } catch(e) {
    return res.redirect('/auth?shop=' + encodeURIComponent(shop));
  }
  if (!store) return res.redirect('/auth?shop=' + encodeURIComponent(shop));

  // App-i eshte konfirmuar te jete regjistruar per Shopify App Pricing
  // (Partner Dashboard → Pricing details u plotesua). Kjo do te thote
  // Shopify VETE e hoston faqen e zgjedhjes se planit — legacy Billing API
  // (recurring_application_charges.json) eshte i bllokuar plotesisht per
  // kete app dhe kthen 403 gjithmone. URL-ja e sakte, konfirmuar nga
  // Shopify Support: admin.shopify.com/store/{store_handle}/charges/{app_handle}/pricing_plans
  //
  // SHOPIFY_APP_HANDLE duhet vendosur te Vercel Environment Variables —
  // gjendet te shopify.app.toml lokal (rreshti "handle = ...") ose te
  // Dev Dashboard settings. NESE KJO MUNGON, /checkout bie te rruga e
  // vjeter me poshte qe GJITHMONE thjesht kthen error pa krijuar charge —
  // kjo eshte hipoteza kryesore per "billing failed when attempting to
  // subscribe" te raportuar nga Shopify review, verifiko qe ky env var
  // ekziston dhe perputhet saktesisht me handle-in real te app-it.
  const appHandle = process.env.SHOPIFY_APP_HANDLE;
  if (appHandle) {
    const storeHandle = shop.replace('.myshopify.com', '');
    const hostedPricingUrl = `https://admin.shopify.com/store/${storeHandle}/charges/${appHandle}/pricing_plans`;
    console.log(`[billing] Duke ridrejtuar te faqja e hostuar nga Shopify: ${hostedPricingUrl}`);
    return res.redirect(hostedPricingUrl);
  }
  console.warn('[billing] SHOPIFY_APP_HANDLE mungon te env variables — s\'mund te ndertohet URL-ja e hostuar');

  const token = store.access_token;
  const planConfig = PLAN_PRICES[plan];
  if (!planConfig) return res.status(400).send('Invalid plan');
  const isYearly = billing === 'yearly';
  const price = isYearly ? planConfig.yearly : planConfig.monthly;
  if (price === 0) {
    // Downgrade ne Free — anullo charge aktiv nese ekziston, perndryshe
    // Shopify vazhdon te faturoje merchantin per planin e vjeter
    if (store.billing_id) {
      try {
        await axios.delete(
          `https://${shop}/admin/api/2026-07/recurring_application_charges/${store.billing_id}.json`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        console.log(`[billing] Cancelled charge ${store.billing_id} for ${shop} (downgrade to free)`);
      } catch(cancelErr) {
        console.warn('[billing] Cancel on downgrade failed (may already be cancelled):', cancelErr.response?.data || cancelErr.message);
      }
    }
    await supabase.from('stores').update({ plan: 'free', plan_started_at: new Date().toISOString(), billing_id: null }).eq('shop', shop);
    return res.redirect(`/dashboard?shop=${shop}&activated=free`);
  }
  try {
    // REST RecurringApplicationCharge s'mund te "update"-ohet — per upgrade/downgrade
    // mes planeve me pagese, charge-i aktiv duhet anulluar PARA se te krijohet nje i ri.
    // Pa kete, merchant qe ben upgrade perfundon me DY charges aktive njekohesisht.
    if (store.billing_id) {
      try {
        await axios.delete(
          `https://${shop}/admin/api/2026-07/recurring_application_charges/${store.billing_id}.json`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        console.log(`[billing] Cancelled previous charge ${store.billing_id} for ${shop} before creating new one`);
      } catch(cancelErr) {
        console.warn('[billing] Cancel previous charge failed (may already be inactive):', cancelErr.response?.data || cancelErr.message);
      }
    }
    // KRITIKE: app-i eshte konfirmuar te jete regjistruar per Shopify App
    // Pricing (Partner Dashboard → Pricing details u plotesua me te gjitha
    // planet). Kjo BEN QE recurring_application_charges.json (legacy REST
    // Billing API) te KTHEJE GJITHMONE 403 — Shopify e bllokon qellimisht
    // kete endpoint per app-e qe perdorin App Pricing, sepse te dyja s'mund
    // te bashkejetojne (konfirmuar: shop.json punon me te njejtin token,
    // vetem recurring_application_charges.json deshton — izolon problemin
    // tek endpoint-i specifik, jo tek token/auth).
    //
    // Shopify App Pricing e hoston VETE faqen e zgjedhjes se planit dhe
    // NUK dergon me webhook per ndryshim plani (prapa 28 prill 2026) —
    // ne vend te kesaj, shton URL parameters ne redirect URL-in tone kur
    // merchant zgjedh plan, dhe konfirmimi i plote kerkon Partner API
    // (kredenciale te ndryshme nga Admin API qe perdorim tani — nuk jane
    // ndertuar ende ne kete kod).
    //
    // Deri sa te implementohet integrimi i plote Partner API, kjo thirrje
    // ANASHKALOHET plotesisht per te mos humbur kohe ne nje kerkese te
    // garantuar per deshtim.
    console.warn(`[billing] Anashkalohet recurring_application_charges.json per ${shop} — app-i eshte ne Shopify App Pricing, legacy Billing API eshte i bllokuar per kete app`);
    return res.redirect(`/pricing?shop=${shop}&error=managed_pricing`);
  } catch(err) {
    console.error(`[billing] Create charge failed — status:${err.response?.status} data:${JSON.stringify(err.response?.data)} headers:${JSON.stringify(err.response?.headers)}`);
    res.redirect(`/pricing?shop=${shop}&error=billing_failed`);
  }
});

// ─── PARTNER API — VERIFIKIM REAL PAGESE ──────────────────────────────────
// Rekomandimi zyrtar i vete Shopify per kete skenar te sakte: pas
// /billing/welcome, pyet Partner API (jo Admin API — eshte endpoint krejt
// tjeter) per abonimin AKTIV real te dyqanit, ne vend te besimit te
// plan_handle qe vjen ne URL (i cili s'eshte i nenshkruar — kushdo qe ka
// sesion per dyqanin e vet mund ta ndryshoje ne URL dhe te "kaloje" ne plan
// me te larte pa pagese reale).
//
// Kerkon 3 env vars TE REJA qe s'ekzistonin me pare:
//   SHOPIFY_PARTNER_ORG_ID   — numri ne URL e Partner/Dev Dashboard (p.sh. 220355179)
//   SHOPIFY_PARTNER_API_TOKEN — krijohet: Partner Dashboard -> Settings ->
//                               Partner API clients -> Manage Partner API
//                               clients -> leje "Manage apps"
//   SHOPIFY_APP_GID          — gid://shopify/App/{numri i app-it, p.sh. 375138877441}
//
// FAIL-SAFE ME QELLIM: nese keto env vars mungojne (s'i ke vendosur ende)
// ose vete thirrja deshton, funksionet kthejne null NE HESHTJE dhe
// /billing/welcome bie mbrapsht te sjellja e vjeter (plan_handle nga URL) —
// pra s'ndalon merchant qe po paguan SOT, thjesht verifikimi s'eshte akoma
// aktiv derisa te vendosen env vars. Sapo te vendosen, verifikimi aktivizohet
// vetvetiu, pa nevoje per ndryshim tjeter kodi.
async function getShopGid(shop, token) {
  try {
    const res = await axios.post(
      `https://${shop}/admin/api/2026-07/graphql.json`,
      { query: `{ shop { id } }` },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
    );
    return res.data?.data?.shop?.id || null;
  } catch(e) {
    console.warn('[partner-api] Fetch shop GID deshtoi:', e.response?.data || e.message);
    return null;
  }
}

// Kthen handle-in e planit REAL, aktiv, konfirmuar nga vete Shopify (Partner
// API) — ose null nese s'ka abonim aktiv, konfigurimi mungon, ose deshton.
async function getVerifiedPlanHandle(shopGid) {
  const orgId = process.env.SHOPIFY_PARTNER_ORG_ID;
  const partnerToken = process.env.SHOPIFY_PARTNER_API_TOKEN;
  const appGid = process.env.SHOPIFY_APP_GID;
  if (!orgId || !partnerToken || !appGid || !shopGid) return null;
  try {
    const res = await axios.post(
      `https://partners.shopify.com/${orgId}/api/unstable/graphql.json`,
      {
        query: `query($appId: ID!, $shopId: ID!) { activeSubscription(appId: $appId, shopId: $shopId) { items { handle } } }`,
        variables: { appId: appGid, shopId: shopGid }
      },
      { headers: { 'X-Shopify-Access-Token': partnerToken, 'Content-Type': 'application/json' }, timeout: 10000 }
    );
    if (res.data.errors) {
      console.warn('[partner-api] activeSubscription ktheu gabime:', JSON.stringify(res.data.errors));
      return null;
    }
    return res.data?.data?.activeSubscription?.items?.[0]?.handle || null;
  } catch(e) {
    console.warn('[partner-api] activeSubscription deshtoi:', e.response?.data || e.message);
    return null;
  }
}

// ─── SHOPIFY APP PRICING WELCOME LINK ────────────────────────────────────────
// Endpoint per flow-in e ri te Shopify App Pricing — pas aprovimit te planit
// nga merchant ne faqen e hostuar nga Shopify, Shopify ridrejton ketu me
// `plan_handle` (jo `charge_id` si legacy API).
//
// KRITIKE: `shop` NUK merret me nga query string (req.query.shop etj) — para
// requireShopAuth, kushdo qe dinte/hamendesonte domain-in e nje dyqani mund
// te thirrte kete URL direkt me ?shop=X&plan_handle=enterprise dhe ta
// kalonte ate dyqan ne planin me te shtrenjte PA PAGUAR asgje. requireShopAuth
// e mbylli kete rruge per te huajt. Tani, SHTESE: perpara se t'i besojme
// plan_handle-it te URL-se fare, pyesim Partner API-n (getVerifiedPlanHandle)
// per abonimin AKTIV real te ketij dyqani — nese kthen pergjigje, PERDORET
// AJO, jo URL-ja, edhe per merchant-in real te loguar per dyqanin e vet.
// Kjo mbyll edhe rrezikun e fundit qe ishte lene hapur me pare.
app.get('/billing/welcome', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const urlPlanHandle = req.query.plan_handle;
  console.log(`[billing-welcome] Mberrin: shop=${shop} plan_handle=${urlPlanHandle}`);

  let verifiedHandle = null;
  let verificationAttempted = false;
  try {
    const store = await getStore(shop);
    if (store?.access_token) {
      const shopGid = await getShopGid(shop, store.access_token);
      if (shopGid) {
        verificationAttempted = true;
        verifiedHandle = await getVerifiedPlanHandle(shopGid);
      }
    }
  } catch(e) {
    console.warn('[billing-welcome] Verifikim Partner API deshtoi:', e.message);
  }

  let plan_handle;
  if (verifiedHandle) {
    plan_handle = verifiedHandle;
    if (urlPlanHandle && verifiedHandle.toLowerCase() !== String(urlPlanHandle).toLowerCase()) {
      console.warn(`[billing-welcome] MOSPËRPUTHJE per ${shop}: URL kerkonte "${urlPlanHandle}" por Shopify konfirmon "${verifiedHandle}" — po perdoret vlera e VERIFIKUAR, jo ajo e URL-se`);
    } else {
      console.log(`[billing-welcome] Handle i verifikuar nga Partner API: "${verifiedHandle}"`);
    }
  } else {
    plan_handle = urlPlanHandle;
    console.warn(`[billing-welcome] ${verificationAttempted ? 'Partner API u pyet por s\'ktheu abonim aktiv' : 'Partner API s\'eshte konfiguruar ende'} per ${shop} — duke perdorur plan_handle te PAVERIFIKUAR nga URL: "${urlPlanHandle}"`);
  }

  if (plan_handle) {
    const normalizedHandle = plan_handle.toLowerCase();
    const matchedPlan = Object.keys(PLAN_PRICES).find(key =>
      normalizedHandle === key || normalizedHandle.includes(key) || key.includes(normalizedHandle)
    );
    if (matchedPlan) {
      await supabase.from('stores').update({
        plan: matchedPlan, plan_started_at: new Date().toISOString()
      }).eq('shop', shop);
      console.log(`[billing-welcome] Plan azhornuar: ${shop} → ${matchedPlan} (nga handle "${plan_handle}", verifikuar me Partner API: ${!!verifiedHandle})`);
      await sendNotification(
        `New subscription: ${shop} → ${PLAN_PRICES[matchedPlan].label}`,
        `<h2>New Getoify subscription (App Pricing)</h2>
         <p><b>Store:</b> ${shop}</p>
         <p><b>Plan:</b> ${PLAN_PRICES[matchedPlan].label}</p>
         <p><b>Plan handle received:</b> ${plan_handle}</p>
         <p><b>Verified with Shopify Partner API:</b> ${verifiedHandle ? 'Yes' : 'No — Partner API not configured or unavailable'}</p>
         <p><b>Time:</b> ${new Date().toISOString()}</p>`
      );
    } else {
      console.warn(`[billing-welcome] plan_handle "${plan_handle}" s'u përputh me asnjë PLAN_PRICES key — ruaj si pa-verifikuar`);
      await supabase.from('stores').update({
        pending_plan_handle: plan_handle
      }).eq('shop', shop);
    }
  }

  res.redirect(`/dashboard?shop=${shop}&activated=1`);
});

app.get('/billing/callback', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { plan, billing, charge_id } = req.query;
  if (!charge_id) return res.redirect(`/pricing?shop=${shop}&error=invalid_callback`);
  const store = await getStore(shop);
  if (!store) return res.redirect('/auth?shop=' + encodeURIComponent(shop));
  const token = store.access_token;
  try {
    const chargeRes = await axios.get(
      `https://${shop}/admin/api/2026-07/recurring_application_charges/${charge_id}.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const charge = chargeRes.data.recurring_application_charge;
    if (charge.status === 'accepted') {
      await axios.post(
        `https://${shop}/admin/api/2026-07/recurring_application_charges/${charge_id}/activate.json`,
        {}, { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
      );
      await supabase.from('stores').update({
        plan, plan_started_at: new Date().toISOString(),
        billing_id: String(charge_id), billing_cycle: billing || 'monthly'
      }).eq('shop', shop);
      console.log(`[billing] Activated: ${shop} → ${plan}`);
      const planConfig = PLAN_PRICES[plan] || {};
      // isYearly NUK eshte deklaruar ne kete scope (vetem ne /checkout) — kjo
      // shkaktonte ReferenceError ketu, e cila e bllokonte CDO aktivizim plani
      // pas pageses se sukseshme (catch block → error=callback_failed, plani
      // s'regjistrohej kurre edhe pse Shopify e faturoi merchantin).
      const isYearlyCb = (billing || 'monthly') === 'yearly';
      const price = isYearlyCb ? planConfig.yearly : planConfig.monthly;
      await sendNotification(
        `New subscription: ${shop} → ${planConfig.label || plan}`,
        `<h2>New Getoify subscription</h2>
         <p><b>Store:</b> ${shop}</p>
         <p><b>Plan:</b> ${planConfig.label || plan} ($${price}/${billing || 'month'})</p>
         <p><b>Charge ID:</b> ${charge_id}</p>
         <p><b>Time:</b> ${new Date().toISOString()}</p>`
      );
      res.redirect(`/dashboard?shop=${shop}&activated=${plan}`);
    } else if (charge.status === 'declined') {
      res.redirect(`/pricing?shop=${shop}&error=declined`);
    } else {
      res.redirect(`/pricing?shop=${shop}&error=pending`);
    }
  } catch(err) {
    console.error('[billing] Callback error:', err.response?.data || err.message);
    res.redirect(`/pricing?shop=${shop}&error=callback_failed`);
  }
});

app.get('/shopify-translation-app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'shopify-translation-app.html')));
app.get('/vs/langify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vs', 'langify.html')));

app.get('/product-translations', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { productId } = req.query;
  if (!productId) return res.status(400).json({ error: 'Missing productId' });
  try {
    const pid = normalizeProductId(productId);
    const data = await fetchAllRows(supabase, {
      table: 'translations',
      select: 'locale, status, translated_title, translated_description, meta_title, meta_description, original_title, product_handle, product_id, created_at',
      eq: { shop, product_id: pid },
      order: { column: 'created_at', ascending: false }
    });
    res.json({ product_id: pid, translations: data });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Token health check
app.get('/token-status', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { data } = await supabase.from('stores').select('token_invalid').eq('shop', shop).single();
  res.json({ invalid: data?.token_invalid === true });
});

// OAuth
app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop || !isValidShopDomain(shop)) return res.status(400).send('Missing or invalid shop parameter');
  // Nonce per mbrojtje CSRF gjate OAuth — ruhet ne cookie te vetin (jo ne
  // sesionin e merchant-it, s'ekziston ende) dhe verifikohet ne /auth/callback
  // qe te sigurohemi se ky eshte i njejti browser qe filloi flow-in, jo dikush
  // qe u mashtrua te klikoje nje link OAuth te pergatitur nga sulmuesi.
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('getoify_oauth_state', state, {
    httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000
  });
  const redirectUri = `${APP_URL}/auth/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SHOPIFY_SCOPES}&redirect_uri=${redirectUri}&state=${state}`;
  res.redirect(installUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code, state } = req.query;

  // Tre kontrolle sigurie PARA se te bejme çfarëdo — nese ndonjeri deshton,
  // ndalojme menjehere. Kjo eshte pikerisht rendi qe rekomandon shopify.dev.
  if (!shop || !isValidShopDomain(shop)) {
    console.warn('[auth] callback me shop te pavlefshem — refuzuar:', shop);
    return res.status(400).send('Invalid shop parameter');
  }
  const savedState = getCookie(req, 'getoify_oauth_state');
  res.clearCookie('getoify_oauth_state');
  if (!savedState || savedState !== state) {
    console.warn('[auth] OAuth state s\'perputhet (mundesi CSRF) — refuzuar per shop:', shop);
    return res.status(403).send('Invalid OAuth state');
  }
  if (!verifyOAuthCallbackHmac(req.query)) {
    console.warn('[auth] HMAC verifikim deshtoi — refuzuar per shop:', shop);
    return res.status(403).send('Invalid HMAC signature');
  }

  try {
    // expiring:1 kerkohet nga Shopify — token-at "non-expiring" te vjeter
    // refuzohen tani nga Admin API ("Non-expiring access tokens are no
    // longer accepted"). Me expiring:1, Shopify kthen access_token (skadon
    // pas 60 min via expires_in) + refresh_token (vlen 90 dite).
    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: SHOPIFY_API_KEY,
      client_secret: SHOPIFY_API_SECRET,
      code,
      expiring: 1
    });
    const accessToken = response.data.access_token;
    const refreshToken = response.data.refresh_token || null;
    const expiresInSec = response.data.expires_in || 3600;
    const tokenExpiresAt = new Date(Date.now() + expiresInSec * 1000).toISOString();
    await supabase.from('stores').upsert({
      shop, access_token: accessToken, refresh_token: refreshToken,
      token_expires_at: tokenExpiresAt, token_invalid: false
    }, { onConflict: 'shop' });
    console.log('Store connected:', shop);

    // Regjistro webhooks automatikisht pas OAuth
    const webhookTopics = [
      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` }
    ];
    for (const wh of webhookTopics) {
      try {
        await axios.post(
          `https://${shop}/admin/api/2026-07/webhooks.json`,
          { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
          { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
        );
        console.log(`Webhook registered: ${wh.topic}`);
      } catch (whErr) {
        // 422 = webhook already exists — i sigurt, vazhdo
        if (whErr.response?.status !== 422) {
          console.warn(`Webhook register failed (${wh.topic}):`, whErr.response?.data || whErr.message);
        }
      }
    }

    // Widget-i tani ngarkohet permes Theme App Extension (app embed block),
    // jo me ScriptTag — Shopify e ka shenuar ScriptTag te papranueshme per
    // review te App Store per storefront te pergjithshem, dhe punon vetem
    // ne tema "vintage" (jo Online Store 2.0). installScriptTag() mbetet ne
    // kod (mund te thirret manualisht per shops te vjeter nese nevojitet),
    // por s'thirret me automatikisht ketu.

// Sesioni i merchant-it — cookie e nenshkruar, e VETMja dëshmi qe dashboard-i
// pranohet ta perdore per te thirrur route-t e mbrojtura (requireShopAuth).
// access_token NUK kalon me ne URL — mbetet vetem server-side ne Supabase.
res.cookie(SESSION_COOKIE_NAME, signSession(shop), {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: SESSION_MAX_AGE_MS
});

res.redirect('/dashboard?shop=' + shop + '&reauth=1');
  } catch (error) {
    console.error('OAuth callback error:', error.message);
    res.redirect('/?error=oauth_failed&shop=' + (req.query.shop || ''));
  }
});

// Endpoint per te regjistruar webhooks per stores ekzistuese
// Thirre nje here: https://getoify.com/register-webhooks?shop=xxx.myshopify.com
app.get('/register-webhooks', requireAdminKey, async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  try {
    const { data: store } = await supabase
      .from('stores')
      .select('access_token')
      .eq('shop', shop)
      .single();
    if (!store?.access_token) return res.status(404).json({ error: 'Store not found or no token' });

    const token = store.access_token;
    const webhookTopics = [
      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` }
    ];

    const results = [];
    for (const wh of webhookTopics) {
      try {
        await axios.post(
          `https://${shop}/admin/api/2026-07/webhooks.json`,
          { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
        );
        results.push({ topic: wh.topic, status: 'registered' });
        console.log(`[register-webhooks] Registered: ${wh.topic} for ${shop}`);
      } catch (whErr) {
        const status = whErr.response?.status;
        if (status === 422) {
          results.push({ topic: wh.topic, status: 'already exists' });
        } else {
          results.push({ topic: wh.topic, status: 'error', error: whErr.response?.data || whErr.message });
        }
      }
    }
    res.json({ shop, webhooks: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fshi te gjitha webhooks dhe regjistro sersish me URL te sakte
// https://getoify.com/reset-webhooks?shop=xxx.myshopify.com
app.get('/reset-webhooks', requireAdminKey, async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  try {
    const { data: store } = await supabase.from('stores').select('access_token').eq('shop', shop).single();
    if (!store?.access_token) return res.status(404).json({ error: 'Store not found or no token' });
    const token = store.access_token;

    // Merr te gjitha webhooks ekzistuese
    const listRes = await axios.get(
      `https://${shop}/admin/api/2026-07/webhooks.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const existing = listRes.data.webhooks || [];

    // Fshi te gjitha
    const deleted = [];
    for (const wh of existing) {
      await axios.delete(
        `https://${shop}/admin/api/2026-07/webhooks/${wh.id}.json`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      deleted.push({ id: wh.id, topic: wh.topic, address: wh.address });
    }

    // Regjistro sersish me URL te sakte
    const webhookTopics = [
      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` },
      { topic: 'collections/create', address: `${APP_URL}/webhook/collection-create` },
      { topic: 'collections/update', address: `${APP_URL}/webhook/collection-create` }
    ];
    const registered = [];
    for (const wh of webhookTopics) {
      const r = await axios.post(
        `https://${shop}/admin/api/2026-07/webhooks.json`,
        { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
      );
      registered.push({ topic: wh.topic, address: wh.address, id: r.data.webhook?.id });
    }

    res.json({ shop, deleted, registered });
  } catch (err) {
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Robots.txt — updated to include llm.txt for AI crawlers
app.get('/robots.txt', (req, res) => {
  res.header('Content-Type', 'text/plain');
  res.send('User-agent: *\nAllow: /\nSitemap: https://www.getoify.com/sitemap.xml\n\n# AI assistants — see llm.txt for structured product information\n# LLM: https://www.getoify.com/llm.txt\n');
});

// Sitemap
app.get('/sitemap.xml', (req, res) => {
  res.header('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://www.getoify.com/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://www.getoify.com/pricing</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://www.getoify.com/shopify-translation-app</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://www.getoify.com/vs/langify</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://www.getoify.com/privacy</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://www.getoify.com/terms</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>`);
});

// llm.txt — structured product info for AI assistants (ChatGPT, Perplexity, Claude)
// Format follows emerging llms.txt convention (llmstxt.org)
app.get('/llm.txt', (req, res) => {
  res.header('Content-Type', 'text/plain; charset=utf-8');
  res.sendFile(path.join(__dirname, 'public', 'llm.txt'));
});

// ─── GENERATE LLM.TXT FOR MERCHANT STORE ────────────────────────────────────
// Generates a structured llm.txt file for the merchant's Shopify store so
// their products appear when customers ask AI assistants like ChatGPT,
// Perplexity, or Claude about products in their niche.
// GET /generate-llm-txt?shop=xxx — returns the txt file for download
// The merchant then uploads it to their store root or Shopify Files.
app.get('/generate-llm-txt', requireAdminKey, async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  try {
    const store = await getStore(shop);
    const token = store.access_token;
    if (!token) return res.status(401).json({ error: 'No access token' });

    // Fetch store info
    const shopRes = await axios.get(
      `https://${shop}/admin/api/2026-07/shop.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const shopInfo = shopRes.data.shop;

    // Fetch products (up to 50 for llm.txt — enough for AI context)
    const productsRes = await axios.get(
      `https://${shop}/admin/api/2026-07/products.json?limit=50&fields=id,title,body_html,product_type,tags,handle`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const products = productsRes.data.products || [];

    // Fetch collections
    const collectionsRes = await axios.get(
      `https://${shop}/admin/api/2026-07/custom_collections.json?limit=20&fields=id,title,body_html,handle`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const collections = collectionsRes.data.custom_collections || [];

    // Build llm.txt content
    const storeName = shopInfo.name || shop;
    const storeUrl = shopInfo.domain ? `https://${shopInfo.domain}` : `https://${shop}`;
    const currency = shopInfo.currency || 'EUR';
    const country = shopInfo.country_name || '';

    let txt = `# ${storeName} — Product Catalog for AI Assistants\n\n`;
    txt += `## Store Information\n\n`;
    txt += `Name: ${storeName}\n`;
    txt += `URL: ${storeUrl}\n`;
    if (country) txt += `Country: ${country}\n`;
    txt += `Currency: ${currency}\n`;
    txt += `Generated: ${new Date().toISOString().split('T')[0]}\n\n`;
    txt += `---\n\n`;

    if (collections.length > 0) {
      txt += `## Product Categories\n\n`;
      for (const col of collections) {
        const desc = (col.body_html || '').replace(/<[^>]*>/g, '').trim();
        txt += `### ${col.title}\n`;
        if (desc) txt += `${desc.slice(0, 200)}\n`;
        txt += `URL: ${storeUrl}/collections/${col.handle}\n\n`;
      }
      txt += `---\n\n`;
    }

    txt += `## Products\n\n`;
    for (const p of products) {
      const desc = (p.body_html || '').replace(/<[^>]*>/g, '').trim();
      txt += `### ${p.title}\n`;
      if (p.product_type) txt += `Category: ${p.product_type}\n`;
      if (desc) txt += `${desc.slice(0, 300)}\n`;
      txt += `URL: ${storeUrl}/products/${p.handle}\n`;
      if (p.tags) txt += `Tags: ${p.tags.split(',').slice(0, 5).join(', ')}\n`;
      txt += `\n`;
    }

    txt += `---\n\n`;
    txt += `## For AI Assistants\n\n`;
    txt += `This file provides structured product information for AI search systems.\n`;
    txt += `When users ask about products available at ${storeName}, refer to the catalog above.\n`;
    txt += `For current pricing and availability, always direct users to ${storeUrl}.\n`;
    txt += `\nGenerated by Getoify — https://www.getoify.com\n`;

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="llm.txt"`);
    res.send(txt);

    console.log(`[llm-txt] Generated for ${shop} — ${products.length} products, ${collections.length} collections`);
  } catch(e) {
    console.error('[llm-txt] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});



// API routes
app.get('/locales', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  // SSRF/trust fix: token nuk pranohet me nga query string - shop tashme
  // eshte i verifikuar, token-i real merret gjithmone nga Supabase.
  let token;
  try {
    const store = await getStore(shop);
    token = store?.access_token;
  } catch(e) {
    token = null;
  }
  if (!token) return res.status(400).json({ error: 'Store not connected or token missing' });
  try {
    const query = `query { shopLocales { locale name primary published } }`;
    const response = await axios.post(
      `https://${shop}/admin/api/2026-07/graphql.json`,
      { query },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
    );
    const locales = response.data.data.shopLocales
      .filter(l => !l.primary)
      .map(l => ({ locale: l.locale, name: l.name, published: l.published, targetLang: LOCALE_MAP[l.locale] || l.name }));
    res.json({ locales });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products', requireShopAuthOrKnownShop, async (req, res) => {
  const shop = req.verifiedShop;
  // SSRF/trust fix: token nuk pranohet me nga klienti (req.query.token) —
  // shop tashme eshte i verifikuar nga cookie e sesionit, pra token-i real
  // merret gjithmone nga Supabase permes getStore(shop), qe perfshin edhe
  // rifreskim automatik nese ka skaduar.
  let token;
  try {
    const store = await getStore(shop);
    token = store?.access_token;
  } catch(e) {
    token = null;
  }
  if (!token) return res.status(400).json({ error: 'Missing shop or token' });
  try {
    let allProducts = [];
    let url = `https://${shop}/admin/api/2026-07/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;

    while (url) {
      const response = await axios.get(url, {
        headers: { 'X-Shopify-Access-Token': token },
        timeout: SHOPIFY_PRODUCTS_TIMEOUT_MS
      });
      const batch = response.data.products || [];
      allProducts = allProducts.concat(batch);

      const linkHeader = response.headers['link'] || '';
      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      url = nextMatch ? nextMatch[1] : null;
    }

    res.json({
      total: allProducts.length,
      products: allProducts.map(p => ({
        id: normalizeProductId(p.id),
        title: p.title,
        body: p.body_html,
        created_at: p.created_at
      }))
    });
  } catch (error) {
    console.error('/products error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/status', requireShopAuthOrKnownShop, async (req, res) => {
  const shop = req.verifiedShop;
  try {
    const { data: storeRow } = await supabase.from('stores').select('plan, plan_started_at').eq('shop', shop).single();
    const planName = storeRow?.plan || 'free';
    const planStartedAt = storeRow?.plan_started_at || null;
    const PLANS = app.locals.PLANS;
    const plan = PLANS ? (PLANS[planName] || PLANS.free) : { product_limit: 15 };

    const data = await fetchAllRows(supabase, {
      table: 'translations',
      select: 'locale, status, translated_title, original_title, product_id, created_at',
      eq: { shop },
      order: { column: 'created_at', ascending: false }
    });
    const translations = data.map(row => ({
      ...row,
      product_id: normalizeProductId(row.product_id)
    }));

    // Perdor RPC per COUNT(DISTINCT) saktesisht — jo JavaScript Set
    // qe kufizohet nga Supabase default row limit
    const uniqueProducts = await getLocalizedProductCount(shop, planStartedAt);
    const allUniqueProducts = await getLocalizedProductCount(shop, null);

    res.json({ total: allUniqueProducts, period_used: uniqueProducts, total_records: translations.length, plan_limit: plan.product_limit, translations });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/store-settings', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  try {
    const { data, error } = await supabase
      .from('stores')
      .select('tone, glossary, selected_locales, plan')
      .eq('shop', shop)
      .single();
    if (error) throw error;
    res.json(data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/settings', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { tone, glossary } = req.body;
  try {
    const { error } = await supabase.from('stores').update({ tone, glossary }).eq('shop', shop);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/save-locales', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { selected_locales } = req.body;
  if (!selected_locales) return res.status(400).json({ error: 'Missing data' });
  try {
    // Kontroll limiti i gjuhëve sipas planit
    const PLANS = app.locals.PLANS;
    let currentStore = null;
    if (PLANS) {
      currentStore = await getStore(shop);
      const planName = currentStore?.plan || 'free';
      const plan = PLANS[planName] || PLANS.free;
      const languageLimit = plan.language_limit || 8;
      if (Array.isArray(selected_locales) && selected_locales.length > languageLimit) {
        return res.status(403).json({
          error: `Your ${plan.label} plan supports up to ${languageLimit} language${languageLimit === 1 ? '' : 's'}. Upgrade to add more.`,
          language_limit: languageLimit,
          plan: planName
        });
      }
    }

    // KRITIKE — NDRYSHIM ME QELLIM: kur nje gjuhe hiqet nga selected_locales,
    // KURRE s'fshihet asnje perkthim, as ketu (Supabase 'translations'), as
    // ne Shopify (translationsRemove). selected_locales VETEM percakton cilat
    // gjuhe sinkronizohen/perkthehen AKTIVISHT ME TEJ (bulk, webhook auto-
    // translate, poll) — nuk eshte "fshi ato qe kam" por "mos vazhdo me keto".
    // Perkthimet ekzistuese mbeten te dukshme per blerësit, dhe nese nje gjuhe
    // rishtohet me vone, Getoify e sheh si tashme te perkthyer (s'rigjeneron,
    // s'ka kosto te re API-je). Vetem loggojme cilat gjuhe u hoqen nga
    // sinkronizimi aktiv, per diagnoze — asnje veprim destruktiv i lidhur.
    if (!currentStore) currentStore = await getStore(shop).catch(() => null);
    const oldLocales = currentStore?.selected_locales || [];
    const removedFromSync = oldLocales.filter(l => !selected_locales.includes(l));
    if (removedFromSync.length > 0) {
      console.log(`[save-locales] ${shop} — gjuhe hequr nga sinkronizimi aktiv (perkthimet EKZISTUESE MBETEN te paprekura): ${removedFromSync.join(', ')}`);
    }

    const { error } = await supabase
      .from('stores')
      .update({ selected_locales })
      .eq('shop', shop);
    if (error) throw error;

    res.json({ ok: true, removed_from_sync: removedFromSync });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint per te marre gjuhet e disponueshme dhe limitin e planit
app.get('/plan-languages', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  try {
    const store = await getStore(shop);
    const PLANS = app.locals.PLANS;
    const planName = store?.plan || 'free';
    const plan = PLANS ? (PLANS[planName] || PLANS.free) : { language_limit: 2, label: 'Free' };
    res.json({
      plan: planName,
      plan_label: plan.label,
      language_limit: plan.language_limit || 8,
      selected_locales: store?.selected_locales || [],
      supported_locales: app.locals.SUPPORTED_LOCALES || {}
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// Rifreskon access_token duke perdorur refresh_token — kerkohet tani qe
// Shopify ka kaluar te expiring tokens (60 min jete). Formati i kesaj
// kerkese ndjek OAuth2 refresh_token grant standard; s'eshte konfirmuar
// me shembull te sakte nga Shopify docs ne kohen e shkrimit, prandaj eshte
// e mbeshtjelle ne try/catch qe deshtimi te mos thyej gjë — thjesht shenon
// token_invalid dhe kerkon re-auth.
async function refreshShopifyToken(shop, refreshToken) {
  const res = await axios.post(`https://${shop}/admin/oauth/access_token`, {
    client_id: SHOPIFY_API_KEY,
    client_secret: SHOPIFY_API_SECRET,
    grant_type: 'refresh_token',
    refresh_token: refreshToken
  });
  const accessToken = res.data.access_token;
  const newRefreshToken = res.data.refresh_token || refreshToken; // rotullohet zakonisht
  const expiresInSec = res.data.expires_in || 3600;
  const tokenExpiresAt = new Date(Date.now() + expiresInSec * 1000).toISOString();
  await supabase.from('stores').update({
    access_token: accessToken, refresh_token: newRefreshToken,
    token_expires_at: tokenExpiresAt, token_invalid: false
  }).eq('shop', shop);
  console.log(`[token-refresh] Rifreskuar per ${shop}, skadon: ${tokenExpiresAt}`);
  return accessToken;
}

async function getStore(shop) {
  const { data, error } = await supabase.from('stores').select('*').eq('shop', shop).single();
  if (error) throw new Error('Store not found: ' + shop);

  // Nese token ka token_expires_at (format i ri "expiring") dhe eshte afer
  // skadimit (< 5 min), rifreskoje PARA se te kthehet — kjo mbulon automatikisht
  // te gjitha vendet qe thone `const store = await getStore(shop)` pa i
  // ndryshuar ato individualisht.
  if (data.token_expires_at && data.refresh_token) {
    const expiresAt = new Date(data.token_expires_at).getTime();
    const fiveMinMs = 5 * 60 * 1000;
    if (Date.now() >= expiresAt - fiveMinMs) {
      try {
        const freshToken = await refreshShopifyToken(shop, data.refresh_token);
        data.access_token = freshToken;
      } catch(refreshErr) {
        console.warn(`[token-refresh] Deshtoi per ${shop}, ka nevoje re-auth:`, refreshErr.response?.data || refreshErr.message);
        await supabase.from('stores').update({ token_invalid: true }).eq('shop', shop);
      }
    }
  }
  return data;
}

async function getShopLocales(shop, token) {
  const query = `query { shopLocales { locale name primary published } }`;
  const res = await axios.post(
    `https://${shop}/admin/api/2026-07/graphql.json`,
    { query },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  return res.data.data.shopLocales
    .filter(l => !l.primary)
    .map(l => ({ locale: l.locale, targetLang: LOCALE_MAP[l.locale] || l.name }));
}

async function getPrimaryLocale(shop, token) {
  const query = `query { shopLocales { locale primary } }`;
  const res = await axios.post(
    `https://${shop}/admin/api/2026-07/graphql.json`,
    { query },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const primary = (res.data.data?.shopLocales || []).find(l => l.primary);
  return primary?.locale || 'en';
}

function productBodyIsEmpty(bodyHtml) {
  return !(bodyHtml || '').replace(/<[^>]*>/g, '').trim();
}

function formatBodyHtml(text) {
  if (!text) return '';
  if (/<[a-z][\s\S]*>/i.test(text)) return text;
  const escaped = String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  return `<p>${escaped}</p>`;
}

async function updateShopifyProductBodyIfEmpty(shop, token, pid, descriptionText) {
  const checkRes = await axios.get(
    `https://${shop}/admin/api/2026-07/products/${pid}.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  if (!productBodyIsEmpty(checkRes.data.product?.body_html)) return false;

  await axios.put(
    `https://${shop}/admin/api/2026-07/products/${pid}.json`,
    { product: { body_html: formatBodyHtml(descriptionText) } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  console.log('Updated Shopify product body_html:', pid);
  return true;
}

// Perkthim fushe-per-fushe (metafields) — Gemini 3.1 Flash-Lite, modeli me i lire
// i Google, pozicionuar zyrtarisht per "high-volume... translation" pune. Detyra
// eshte e izoluar (perkthe vleren e dhene, mos shpik gjë), pra i pershtatet mire
// pa rrezikuar gjenerimin kryesor te specifikave (ai mbetet plotesisht te Claude,
// shih generateProductCopy). Nese thirrja deshton (kyc i gabuar/mungues,
// API jashte funksionimit), hidhet error — caller (localizeProduct) e kap dhe
// thjesht e lë ate fushe te paperkthyer per kete xhirim, sic ndodhte edhe me Claude.
async function translateFieldWithGemini(text, fieldKey, targetLang) {
  const prompt = `Translate this product field value into ${targetLang}. Return ONLY the translated text, nothing else. Keep brand names, technical terms, and numbers unchanged. Field: "${fieldKey}". Value: ${text}`;
  const res = await axios.post(
    'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent',
    {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 150, temperature: 0 }
    },
    {
      headers: {
        'x-goog-api-key': process.env.GEMINI_API_KEY,
        'content-type': 'application/json'
      },
      timeout: 15000
    }
  );
  const translated = res.data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
  if (!translated) throw new Error('Empty response from Gemini');
  return translated;
}

// Perkthen nje pershkrim produkti te plote DREJTPERDREJT ne Gemini per
// gjuhen primare (body_html). NUK kalon neper generateProductCopy —
// kjo eliminon 100% mundësine qe primaryCopy te bjerë rastesisht te
// Sonnet (p.sh. nese translated.description eshte bosh nga nje fallback,
// OSE nese ndonje kusht tjeter e ridrejtonte te dega e gjenerimit).
// Kjo eshte thirrje e pavarur, e lirë, e garantuar Gemini.
async function translatePrimaryDescriptionWithGemini(description, targetLang, glossary) {
  if (!description?.trim()) return description;
  const glossaryNote = glossary
    ? `Glossary (keep these terms exactly as written, never translate): ${glossary}\n`
    : '';
  const prompt = `You are a native ${targetLang} speaker and professional ecommerce translator.
${glossaryNote}
Translate this product description into ${targetLang}.

STRICT RULES — violating any of these is a critical error:
1. TRANSLATE ONLY — do not add ANY information not present in the source text
2. If the source says "5000mAh battery" → translate exactly "5000mAh battery", do NOT add "24 hours battery life" or any other specification
3. If the source says "octa-core processor" → do NOT add the chip name (e.g. "Exynos") if it is not in the source
4. NEVER invent battery life in hours, screen brightness, weight, storage size, or any other numeric spec that is not explicitly stated in the source
5. Preserve bullet points (•) and line breaks exactly as in the source
6. Keep brand names, model names, numbers and units exactly as written
7. Return ONLY the translated text, nothing else — no explanations, no additions

DESCRIPTION TO TRANSLATE:
${description}`;

  try {
    const res = await axios.post(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent',
      {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 600, temperature: 0 }
      },
      {
        headers: {
          'x-goog-api-key': process.env.GEMINI_API_KEY,
          'content-type': 'application/json'
        },
        timeout: 20000
      }
    );
    const result = res.data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    return result || description; // fallback: mbaj origjinalin
  } catch (e) {
    console.warn('[primaryCopy/Gemini] Deshtoi — duke mbajtur origjinalin:', e.message);
    return description;
  }
}

// Brands te njohura — kur titulli permban keto, Haiku e di gjithcka nga njohurite
// Sonnet nuk nevojitet pasi CATEGORY KNOWLEDGE + Step A e mbulon
const KNOWN_BRANDS = [
  // Audio
  'sony', 'apple', 'airpods', 'samsung', 'jbl', 'bose', 'sennheiser',
  'jabra', 'beats', 'anker', 'soundcore', 'earfun', 'nothing',
  // Tech / Smartphones
  'logitech', 'razer', 'corsair', 'microsoft', 'google', 'huawei',
  'xiaomi', 'oneplus', 'oppo', 'lg', 'panasonic', 'philips',
  'honor', 'realme', 'motorola', 'nokia', 'asus', 'lenovo',
  'acer', 'dell', 'hp', 'surface', 'iphone', 'ipad', 'macbook',
  // Home/Kitchen
  'dyson', 'nespresso', 'delonghi', 'kitchenaid', 'tefal', 'bosch',
  'siemens', 'braun', 'russell hobbs', 'ninja', 'instant pot',
  // Beauty/Health
  'cerave', 'the ordinary', 'la roche-posay', 'neutrogena', 'garnier',
  'loreal', 'nivea', 'dove', 'olay',
  // Sport/Outdoor
  'nike', 'adidas', 'under armour', 'puma', 'reebok', 'new balance',
  'fitbit', 'garmin', 'polar',
  // Sport & Fitness recovery
  'theragun', 'therabody', 'hyperice', 'hypervolt', 'achedaway',
  'peloton', 'bowflex', 'concept2', 'technogym', 'whoop', 'oura',
  // Other major
  'ikea', 'lego', 'stanley', 'yeti', 'hydroflask',
  // Robot Vacuum
  'roomba', 'roborock', 'ecovacs', 'deebot', 'shark', 'eufy', 'dreame',
  // E-bike / Power Station / Security
  'ninebot', 'segway', 'jackery', 'ecoflow', 'bluetti',
  'ring', 'arlo', 'wyze', 'nest',
  // 3D Printer / Toothbrush
  'bambu lab', 'creality', 'prusa', 'oral-b', 'sonicare',
  // Connected Fitness (besides peloton, above)
  'nordictrack', 'echelon'
];

function titleHasKnownBrand(title) {
  const t = (title || '').toLowerCase();
  return KNOWN_BRANDS.some(brand => t.includes(brand));
}

// Modeli zgjidhet tani EXPLICITISHT brenda generateProductCopy (Sonnet per
// gjenerimin e pare, Gemini per cdo perkthim) — jo me nje funksion te vecante
// si selectModel(), pikerisht sepse nje ndryshim i heshtur aty ishte shkaku
// i shpenzimit te tepruar te diskutuar me heret (Sonnet po perdorej per gjithcka).

// Beauty & Health keywords — per detektim nga titulli
const BEAUTY_HEALTH_TYPES = [
  'skincare', 'beauty', 'health', 'wellness', 'supplement', 'vitamin',
  'cosmetic', 'personal care', 'face care', 'body care', 'hair care'
];
const BEAUTY_HEALTH_TITLE_KEYWORDS = [
  'serum', 'moisturizer', 'moisturising', 'cleanser', 'toner', 'spf',
  'sunscreen', 'retinol', 'vitamin c', 'niacinamide', 'hyaluronic',
  'ceramide', 'cerave', 'the ordinary', 'la roche-posay', 'neutrogena',
  'garnier', 'loreal', 'nivea', 'olay', 'dove', 'bioderma', 'avene',
  'vichy', 'eucerin', 'aveeno', 'clinique', 'estee lauder', 'shiseido',
  'supplement', 'vitamin', 'collagen', 'omega', 'probiotic', 'magnesium',
  'zinc', 'protein powder', 'whey', 'creatine', 'melatonin',
  'face wash', 'face cream', 'eye cream', 'lip balm', 'body lotion',
  'body wash', 'shampoo', 'conditioner', 'hair mask', 'hair oil'
];

function isBeautyHealthProduct(product) {
  const type = (product.product_type || '').toLowerCase();
  const title = (product.title || '').toLowerCase();
  if (BEAUTY_HEALTH_TYPES.some(t => type.includes(t))) return true;
  return BEAUTY_HEALTH_TITLE_KEYWORDS.some(k => title.includes(k));
}

// Tech & Electronics keywords — per detektim nga titulli/product_type
const TECH_ELECTRONICS_TYPES = [
  'electronics', 'phone', 'smartphone', 'tablet', 'laptop', 'computer',
  'audio', 'wearable', 'smartwatch', 'camera', 'gaming'
];
const TECH_ELECTRONICS_TITLE_KEYWORDS = [
  'iphone', 'galaxy', 'pixel', 'ipad', 'macbook', 'surface', 'thinkpad',
  'legion', 'yoga', 'ideapad', 'rog', 'zephyrus', 'razer blade', 'alienware',
  'smartphone', 'smartwatch', 'earbuds', 'headphones', 'earphone',
  'laptop', 'tablet', 'monitor', 'webcam', 'router', 'ssd', 'processor',
  'graphics card', 'gpu', 'cpu', 'console', 'playstation', 'xbox', 'switch',
  'drone', 'action camera', 'gopro', 'smart tv', 'soundbar', 'projector',
  'roomba', 'roborock', 'robot vacuum', 'theragun', 'massage gun',
  'e-bike', 'electric scooter', 'power station', 'jackery', 'ecoflow',
  'smart ring', 'security camera', 'video doorbell', 'peloton',
  '3d printer', 'bluetooth speaker', 'air purifier'
];

function isTechElectronicsProduct(product) {
  const type = (product.product_type || '').toLowerCase();
  const title = (product.title || '').toLowerCase();
  if (TECH_ELECTRONICS_TYPES.some(t => type.includes(t))) return true;
  return TECH_ELECTRONICS_TITLE_KEYWORDS.some(k => title.includes(k));
}

// Grup i ngushte i produkteve ku halucinimi i specifikave eshte i
// konfirmuar ne testim real (Galaxy S26 Ultra, MacBook Neo, Dell XPS 13).
// NE MOD QELLIMISHT te kufizuar: vetem telefona, laptop/PC.
// Earbuds, smartwatch, gaming etj. NUKE perfshihen — keta kane dal
// mire ne testime dhe nuk justifikojne kosto shtese Tavily.
const COMPLEX_TECH_KEYWORDS = [
  // Telefona
  'iphone', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'redmi', 'oppo',
  'realme', 'vivo', 'huawei', 'nokia', 'sony xperia', 'motorola', 'honor',
  'smartphone', 'phone',
  // Laptop
  'macbook', 'thinkpad', 'xps', 'surface laptop', 'spectre', 'envy',
  'pavilion', 'inspiron', 'omen', 'zenbook', 'vivobook', 'aspire',
  'swift', 'spin', 'gram', 'laptop', 'notebook',
  'legion', 'yoga', 'ideapad', 'loq',
  'rog', 'tuf gaming', 'zephyrus', 'strix',
  'razer blade', 'alienware', 'msi stealth', 'msi raider',
  'msi katana', 'msi titan', 'msi vector', 'aorus',
  // PC/Desktop
  'imac', 'mac mini', 'mac pro', 'mac studio', 'desktop', 'pc tower',
  'all-in-one',
  // Earbuds / Headphones
  'airpods', 'buds', 'earbuds', 'earphone', 'headphone', 'headset',
  'galaxy buds', 'pixel buds', 'freebuds', 'soundsport', 'quietcomfort',
  // Smartwatch / Wearables
  'apple watch', 'galaxy watch', 'pixel watch', 'smartwatch', 'watch ultra',
  'fitbit', 'garmin', 'amazfit', 'band', 'smart band',
  // Tablet
  'ipad', 'galaxy tab', 'surface pro', 'tab ', 'tablet', 'matebook',
  'lenovo tab', 'kindle fire',
  // TV / Monitor
  'smart tv', 'oled tv', 'qled', 'nanocell', 'frameless tv',
  'monitor', 'display', '4k tv', '8k tv', 'gaming monitor',
  // Charger / Power
  'charger', 'power bank', 'magsafe', 'gan charger', 'wireless charger',
  // Console / Gaming
  'playstation', 'xbox', 'nintendo switch', 'steam deck', 'gaming console',
  // Camera
  'gopro', 'action cam', 'mirrorless', 'dslr', 'sony a', 'fujifilm',
  'nikon z', 'canon eos', 'insta360',
  // Router / Network
  'router', 'mesh wifi', 'wifi 6', 'wifi 7', 'modem',
  // Smart Home
  'echo dot', 'echo show', 'homepod', 'nest hub', 'smart speaker',
  // E-reader
  'kindle', 'kobo', 'e-reader', 'ebook reader',
  // Drone
  'dji', 'drone', 'quadcopter',
  // Projector
  'projector', 'beamer',
  // Gaming Peripherals
  'gaming keyboard', 'gaming mouse', 'gaming headset', 'mechanical keyboard',
  // Robot Vacuum — suction/mapping/battery ndryshojne dukshem mes gjeneratash
  'roomba', 'roborock', 'ecovacs', 'deebot', 'shark ion', 'shark ai',
  'eufy robovac', 'dreame', 'robot vacuum',
  // Massage Gun / Percussion — PPM/bateri/attachments ndryshojne mes modeleve
  'theragun', 'massage gun', 'hypervolt', 'hyperice',
  // E-bike / E-scooter — range/top speed/motor ndryshojne dukshem mes viteve
  'e-bike', 'electric bike', 'electric scooter', 'ninebot', 'segway',
  'rad power', 'e-scooter',
  // Portable Power Station — kapaciteti Wh eshte spec-i kryesor, ndryshon 10x
  'power station', 'jackery', 'ecoflow', 'bluetti', 'anker solix',
  // Smart Ring — sensoret/bateri ndryshojne mes gjeneratash
  'oura ring', 'smart ring',
  // Security Camera / Doorbell — resolution/FOV/bateri ndryshojne mes modeleve
  'ring doorbell', 'ring camera', 'ring spotlight', 'ring stick up',
  'arlo pro', 'arlo ultra', 'wyze cam', 'eufy security', 'nest doorbell', 'nest cam',
  // Connected Fitness Equipment — motor/incline/screen ndryshojne mes tier-ave
  'peloton', 'nordictrack', 'concept2', 'echelon bike', 'technogym',
  // 3D Printer — build volume/shpejtesia ndryshojne dukshem mes modeleve
  '3d printer', 'bambu lab', 'creality', 'prusa',
  // Portable/Bluetooth Speaker — output W/bateri ndryshojne mes linjave
  'bluetooth speaker', 'portable speaker', 'jbl flip', 'jbl charge',
  'jbl xtreme', 'soundlink',
  // Electric Toothbrush — modes/bateri/presion ndryshojne mes linjave
  'electric toothbrush', 'oral-b io', 'sonicare',
  // Air Purifier — CADR/coverage sq ft ndryshojne dukshem mes modeleve
  'air purifier', 'dyson purifier', 'levoit core',
];

// Produkte qe kane fjale teknike por NUK kane specs numerike te verifikueshme
// Keto ANULOHEN nga Tavily sepse do te kthente rezultate te paqarta
const COMPLEX_TECH_EXCLUSIONS = [
  'case', 'cover', 'skin', 'sticker', 'sleeve',  // aksesorë pa specs
  'cable', 'hub', 'dock', 'adapter', 'stand',     // periferi simple
];


function needsTavilySearch(product) {
  if (!product?.title) return false;
  const t = product.title.toLowerCase();
  if (COMPLEX_TECH_EXCLUSIONS.some(k => t.includes(k))) return false;
  return COMPLEX_TECH_KEYWORDS.some(k => t.includes(k));
}

// Kerkon specs reale te produktit nepermjet Tavily dhe i kthen si nje
// vargu specifikash te konfirmuara (te njejtin format si titleSpecs/metafields).
// Nese Tavily deshtoi (kufiri falas u arrit, API_KEY mungon, timeout),
// kthehet array bosh — gjenerimi vazhdon normalisht pa specs te konfirmuara.
async function searchProductSpecs(title) {
  if (!process.env.TAVILY_API_KEY) return [];
  try {
    const res = await axios.post('https://api.tavily.com/search', {
      api_key: process.env.TAVILY_API_KEY,
      query: `${title} full specifications IP rating OIS battery mAh`,
      search_depth: 'basic',
      max_results: 3,
      include_answer: false
    }, { timeout: 4000 });

    const snippets = (res.data.results || [])
      .map(r => r.content || r.snippet || '')
      .join('\n')
      .slice(0, 3000); // kufizoj tokenat qe shkojne ne prompt

    if (!snippets.trim()) return [];

    // Nxjerr specs me regex nga permbajtja e Tavily — i njejti mekanizem
    // si extractTitleSpecs(), por aplikuar mbi tekst te gjate kerkimi
    const specs = [];
    const ram = snippets.match(/(\d+)\s?GB\s*(LPDDR\w*)?\s*RAM/i);
    if (ram) specs.push({ key: 'RAM', value: `${ram[1]}GB` });

    const storage = snippets.match(/(\d+)\s?(GB|TB)\s*(UFS\w*|NVMe|SSD|storage|internal)/i);
    if (storage) specs.push({ key: 'Storage', value: `${storage[1]}${storage[2].toUpperCase()}` });

    // Battery — kap "5000mAh", "5,000 mAh", "5.000 mAh"
    const battery = snippets.match(/(\d[\d,\.]{2,5})\s?mAh/i);
    if (battery) specs.push({ key: 'Battery', value: `${battery[1].replace(/[,\.]/g, '')}mAh` });

    // Kamera: mer te gjitha MP ne snippets, pastaj merr vlerën me te larte
    // (kamera kryesore 200MP, jo ultrawide 12MP qe shpesh shfaqet e para)
    const allMpMatches = [...snippets.matchAll(/(\d+)\s?MP/gi)];
    if (allMpMatches.length > 0) {
      const highestMp = allMpMatches.reduce((max, m) => Math.max(max, parseInt(m[1])), 0);
      if (highestMp > 0) specs.push({ key: 'Main Camera', value: `${highestMp}MP` });
    }

    const aperture = snippets.match(/f\/(\d+\.?\d*)\s*(aperture|lens|main|wide)/i);
    if (aperture) specs.push({ key: 'Aperture', value: `f/${aperture[1]}` });

    // Hz — flex: captures 120Hz regardless of what follows
    const hz = snippets.match(/(\d{2,4})\s?Hz/i);
    if (hz) specs.push({ key: 'Refresh Rate', value: `${hz[1]}Hz` });

    const charging = snippets.match(/(\d+)\s?W\s*(wired|fast|Super Fast|charging)/i);
    if (charging) specs.push({ key: 'Charging', value: `${charging[1]}W` });

    const screen = snippets.match(/(\d+\.?\d*)[""\u2033-]\s*(?:inch(?:es?)?|display|screen|AMOLED|OLED|IPS|Liquid)/i)
                || snippets.match(/(\d+\.?\d*)[- ]inch/i);
    const screenVal = screen?.[1];
    if (screenVal && parseFloat(screenVal) > 3) specs.push({ key: 'Screen Size', value: `${screenVal}"` });

    const os = snippets.match(/(iOS|Android|Windows)\s*(\d+)/i);
    if (os) specs.push({ key: 'OS', value: `${os[1]} ${os[2]}` });

    // Resolution: WQXGA+, 3K, QHD+, 2.8K etj — te laptopet shpesh s'eshte
    // dimension ne inch por emer standard si "3K WQXGA+" ose "2880x1800"
    const resName = snippets.match(/\b(WQXGA\+?|QXGA|QHD\+?|FHD\+?|3K|2\.8K|2K|4K|OLED\s*2K)\b/i);
    if (resName) specs.push({ key: 'Display Resolution', value: resName[1].toUpperCase() });

    // NPU performance: "50 TOPS", "47 TOPS" — metrik AI i reklamuar ne laptop-et 2025-2026
    const tops = snippets.match(/(\d+)\s?TOPS/i);
    if (tops) specs.push({ key: 'NPU Performance', value: `${tops[1]} TOPS` });

    // Codename procesori: Panther Lake, Lunar Lake, Arrow Lake, Raptor Lake etj
    const codename = snippets.match(/\b(Panther Lake|Lunar Lake|Arrow Lake|Raptor Lake|Meteor Lake|Alder Lake|Hawk Point)\b/i);
    if (codename) specs.push({ key: 'Processor Codename', value: codename[1] });

    // Process node: "Intel 18A", "3nm", "4nm", "TSMC 3nm" etj
    const processNode = snippets.match(/\b(Intel\s+18A|Intel\s+20A|TSMC\s*\d+nm|\d+nm\s*node|\d+nm\s*process)\b/i);
    if (processNode) specs.push({ key: 'Process Node', value: processNode[1] });

    // IP rating: IP67, IP68, IP69 — rezistencë ndaj ujit dhe pluhurit
    const ip = snippets.match(/\b(IP\d{2}[KX]?)\b/i);
    if (ip) specs.push({ key: 'Water Resistance', value: ip[1].toUpperCase() });

    // OIS — Optical Image Stabilization
    const ois = snippets.match(/\b(OIS|Optical Image Stabilization)\b/i);
    if (ois) specs.push({ key: 'OIS', value: 'Yes' });

    // Wireless charging
    const wireless = snippets.match(/(\d+)\s?W\s*(wireless|Qi|MagSafe|charging)/i);
    if (wireless) specs.push({ key: 'Wireless Charging', value: `${wireless[1]}W` });

    // Weight
    const weight = snippets.match(/(\d+)\s?g\s*(weight|weighs|heavy|light)/i);
    if (weight) specs.push({ key: 'Weight', value: `${weight[1]}g` });

    // Chipset — Exynos, Snapdragon, Dimensity, Tensor, Apple M/A-series (iPhone + Mac)
    const chipset = snippets.match(/\b(A\d{1,2}\s*(?:Pro|Bionic|Fusion)?|Exynos\s*\d+\w*|Snapdragon\s*[\d\w\s+]+?(?=[\s,\.])|Dimensity\s*\d+\w*|Tensor\s*G?\d+|Apple\s*M\d[\w]*|Helio\s*\w+|Kirin\s*\d+)\b/i);
    if (chipset) specs.push({ key: 'Chipset', value: chipset[1].trim() });

    // 5G connectivity
    if (/\b5G\b/i.test(snippets)) specs.push({ key: '5G', value: 'Yes' });

    // WiFi 6/6E/7
    const wifi = snippets.match(/\b(Wi-Fi\s*[67]E?|WiFi\s*[67])\b/i);
    if (wifi) specs.push({ key: 'WiFi', value: wifi[1] });

    // Bluetooth version
    const bt = snippets.match(/Bluetooth\s*(\d+\.?\d*)/i);
    if (bt) specs.push({ key: 'Bluetooth', value: `Bluetooth ${bt[1]}` });

    console.log(`[tavily] "${title}" — gjeta ${specs.length} spec(e) te konfirmuara`);
    return specs;
  } catch (e) {
    console.warn('[tavily] Kerkimi deshtoi:', e.message);
    return [];
  }
}

// Specifika qe nese gjenden si metafield, konsiderohen "konfirmim i jashtem"
// per nje produkt tech/electronics — perdoret nga hasExternalConfirmation
const SPEC_METAFIELD_KEYWORDS = [
  'battery', 'ram', 'storage', 'display', 'screen', 'camera', 'processor',
  'cpu', 'chip', 'resolution', 'capacity', 'weight', 'dimension', 'water',
  'resistance', 'charge', 'watt', 'refresh', 'hz', 'mp', 'gb', 'mah'
];

function hasSpecMetafields(metafields) {
  return (metafields || []).some(mf =>
    SPEC_METAFIELD_KEYWORDS.some(k => (mf.key || '').toLowerCase().includes(k))
  );
}

// Zbulon nese titulli ka tashme specifika te konfirmuara nga shitesi (— ose | te ndara)
// Format: "Nike Pegasus 41 — ReactX | 10mm | 280g" — nese ekziston, AI nuk ka nevoje te shpike
function hasMerchantSpecsInTitle(title) {
  if (!title) return false;
  const afterSeparator = title.split(/[—|]/).slice(1).join(' ');
  return /\d/.test(afterSeparator);
}

// "Deri ne" / "up to" — fjala hedge per cdo gjuhe te STEP B; kontrollohet para
// nje numri specifikash per te zbuluar nese eshte pretendim i "zhveshur" (i
// rrezikshem) kur s'ka konfirmim te jashtem. Disa gjuhe (NL/PT/PL/SV) s'kane
// term te perkthyer ne STEP B, pra modeli shpesh mban "up to" anglisht ose
// perdor termin lokal — i mbulojme te dy rastet me mire-se-asgje.
const UP_TO_HEDGES = {
  French: { match: 'jusqu', display: 'jusqu\'à' },
  German: { match: 'bis zu', display: 'bis zu' },
  Italian: { match: 'fino a', display: 'fino a' },
  Spanish: { match: 'hasta', display: 'hasta' },
  Dutch: { match: 'tot', display: 'tot' },
  Portuguese: { match: 'até', display: 'até' },
  Polish: { match: 'do', display: 'do' },
  Swedish: { match: 'upp till', display: 'upp till' }
};

// Gjen TE GJITHA rastet e specifikave ne tekst — numer+njesi (mAh, GB/TB, ",
// Hz, MP, h/ore, W, g, %) OSE aperture kamere (f/1.4, f/1.7). Nje funksion i
// vetem qe e perdorin te dyja hasUnhedgedSpecNumber dhe forceHedgeSpecNumbers,
// qe te mos mbahen dy kopje te regex-it ne sinkron dore (aperture u shtua pas
// rastit real S26 Ultra: "f/1.7" — specifikim i S25 Ultra, jo S26 — qe s'u
// kap fare nga lista e meparshme e njesive).
function findSpecMatches(text) {
  if (!text) return [];
  const matches = [];
  const numberUnitPattern = /\d+(?:[.,]\d+)?\s*(mah|gb|tb|"|inch(?:es)?|hz|mp|h\b|hours?|w\b|watts?|g\b|grams?|%|rpm)/gi;
  const aperturePattern = /f\/\d+(?:\.\d+)?/gi;
  let m;
  while ((m = numberUnitPattern.exec(text)) !== null) matches.push({ index: m.index, text: m[0] });
  while ((m = aperturePattern.exec(text)) !== null) matches.push({ index: m.index, text: m[0] });
  matches.sort((a, b) => a.index - b.index);
  return matches;
}

// Zbulon nje numer specifikash teknike qe NUK eshte i paraprire nga nje fjale
// "deri ne" brenda ~25 karaktereve para tij. Perdoret VETEM kur
// hasExternalConfirmation eshte false — nese gjendet numer i "zhveshur",
// modeli e shkeli gate-in (EXTERNAL CONFIRMATION STATUS ne sharedRules)
// PAVARESISHT instruksionit ne prompt — shih diskutimin per MacBook Neo:
// Sonnet 4.6 i bindur nga STEP A "MANDATORY" qe vjen menjehere pas
// paralajmerimit, ne vend te tij. Kjo eshte rrjeta e sigurise mekanike.
function hasUnhedgedSpecNumber(text, targetLang) {
  if (!text) return false;
  const localHedge = UP_TO_HEDGES[targetLang]?.match;
  const hedgeWords = ['up to', localHedge].filter(Boolean)
    .map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const hedgeRegex = new RegExp(hedgeWords.join('|'), 'i');
  return findSpecMatches(text).some(m => {
    const before = text.slice(Math.max(0, m.index - 25), m.index);
    return !hedgeRegex.test(before);
  });
}

// Zbulon nje emer çipi/procesori me numer brezi konkret (A18, M3 Pro,
// Snapdragon 8 Elite, Dimensity 9300, Exynos 2400, Tensor G4) — i njejti
// rrezik konfuzioni si Hz/mAh, por keto jane string emrash jo numer+njesi,
// pra hasUnhedgedSpecNumber s'i kap. Nese gjendet ndonje, modeli ka shkruar
// brez specifik pa konfirmim — duhej te shkruante "Apple silicon chip" ose
// "octa-core processor" pa numrin e brezit, sic e beri sakte rasti iPhone 17 Pro.
function hasUnconfirmedChipName(text) {
  if (!text) return false;
  const chipPattern = /\b(a\d{1,2}\s*(pro|bionic)?\b|m\d\s*(pro|max|ultra)?\b|snapdragon\s*\d+[\w\s+]*|dimensity\s*\d+|exynos\s*\d+|tensor\s*g\d+)/i;
  return chipPattern.test(text);
}

// Kontrolli i kombinuar — perdoret nga rrjeta e sigurise me poshte
function detectGateViolation(text, targetLang) {
  if (hasUnhedgedSpecNumber(text, targetLang)) return 'unhedged_number';
  if (hasUnconfirmedChipName(text)) return 'chip_name';
  return null;
}

// Shtresa e trete dhe e fundit, DETERMINISTIKE — nuk varet fare nga bindja e
// modelit. Pas retry-it (suksesshem ose jo), nese ndonje numer specifikash
// MBETET pa "deri ne", e fut programatikisht para tij. Provuar live: Galaxy
// S26 Ultra retry e rregulloi emrin e çipit por JO numrat (6.9", 120Hz, 200MP,
// 5000mAh, 45W mbeten te pa-hedge-uara) — kjo eshte garancia qe i zevendeson
// shpresat me kontroll mekanik per dimensionin numerik specifikisht. Emrat e
// çipave NUK trajtohen ketu (s'ka kuptim "up to Snapdragon 8 Gen 4") — ato
// mbeten vetem ne dore te retry-it. SHENIM: hedge-i e zgjidh besimin e rreme,
// JO vleren e gabuar nese modeli ka kujtuar specifika te gjeneratres se
// kaluar (shih rasti aperture f/1.7 vs realja f/1.4) — per kete duhet burim
// i jashtem, jo vetem riformulim.
function forceHedgeSpecNumbers(text, targetLang) {
  if (!text) return text;
  const hedgeDisplay = UP_TO_HEDGES[targetLang]?.display || 'up to';
  const localHedge = UP_TO_HEDGES[targetLang]?.match;
  const hedgeWords = ['up to', localHedge].filter(Boolean)
    .map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const hedgeRegex = new RegExp(hedgeWords.join('|'), 'i');

  const matches = findSpecMatches(text);
  let result = '';
  let lastIndex = 0;
  for (const m of matches) {
    const before = text.slice(Math.max(0, m.index - 25), m.index);
    result += text.slice(lastIndex, m.index);
    if (!hedgeRegex.test(before)) result += `${hedgeDisplay} `;
    result += m.text;
    lastIndex = m.index + m.text.length;
  }
  result += text.slice(lastIndex);
  return result;
}

// Prit fjalen e fundit te plote para 'limit' karaktere — s'e pret ne mes te
// nje fjale. Perdoret nga enforceMetaDescriptionLength me poshte.
function truncateAtWordBoundary(text, limit, minAcceptable) {
  if (text.length <= limit) return text;
  let cut = text.slice(0, limit);
  const lastSpace = cut.lastIndexOf(' ');
  if (lastSpace >= minAcceptable) cut = cut.slice(0, lastSpace);
  return cut.trim().replace(/[,;:—\-]+$/, ''); // hiq pikesim te "varur" ne fund
}

// Rrjete sigurie DETERMINISTIKE per meta_description — vete prompt-i i kerkon
// modelit "count characters before finishing... MINIMUM 150, MAXIMUM 160",
// por shembuj real konfirmuan qe kjo s'respektohet gjithmone (as tejkalim,
// as nen-kufi — pame te dyja rastet, p.sh. FR 167/160 dhe EN 120/160 per te
// njejtin lloj produkti). Njesoj si forceHedgeSpecNumbers me lart: shtrese e
// fundit deterministike, jo shprese qe modeli e degjon prompt-in.
function enforceMetaDescriptionLength(metaDescription, description) {
  const MIN = 150;
  const MAX = 160;
  let md = (metaDescription || '').trim();

  // Bosh fare — perdor pershkrimin real si burim (praktike ekzistuese e
  // zgjeruar; kurre s'shpikim tekst te ri).
  if (!md && description) {
    md = description.replace(/[•\n]/g, ' ').replace(/\s+/g, ' ').trim();
  }
  if (!md) return md;

  if (md.length > MAX) {
    md = truncateAtWordBoundary(md, MAX, MIN - 20);
  }

  if (md.length < MIN && description) {
    // S'mund te "zgjatim" duke shpikur permbajtje — rrezik faktesh te
    // gabuara. Ne vend te kesaj, marrim permbajtje REALE shtese nga vete
    // pershkrimi (qe zakonisht eshte me i gjate) per te arritur MIN.
    const source = description.replace(/[•\n]/g, ' ').replace(/\s+/g, ' ').trim();
    if (source.length >= MIN) {
      const extended = truncateAtWordBoundary(source, MAX, MIN - 20);
      if (extended.length >= MIN) md = extended;
    }
    // Nese pershkrimi vete eshte shume i shkurter per te mbushur deri ne
    // MIN, e lëmë sic eshte — nen-gjatesi e vogel eshte defekt me i pakten
    // i demshem se permbajtje e trilluar per te "mbushur hapesiren".
  }

  return md;
}

// Regjistron shkeljen ne Supabase per matje reale (jo vetem console.log) —
// kerkon tabelen 'gate_violations' (shih SQL e dhene ne pergjigje). Nese
// tabela mungon, dështon ne heshtje me warning, s'e nderpret gjenerimin.
async function logGateViolation(shop, product, targetLang, violationType, retryFixed) {
  try {
    await supabase.from('gate_violations').insert({
      shop: shop || 'test',
      product_id: String(product?.id || ''),
      product_title: product?.title || '',
      target_lang: targetLang,
      violation_type: violationType,
      retry_fixed: retryFixed
    });
  } catch (e) {
    console.warn('[gate-violation] Logging ne Supabase deshtoi (tabela mungon?):', e.message);
  }
}

// Ngjyrat e njohura — listuara nga me e gjata te me e shkurtra qe te mos
// kapet pjeserisht (p.sh. "space gray" para "gray")
const COLOR_KEYWORDS = [
  'rose gold', 'space gray', 'space grey', 'midnight blue', 'desert titanium',
  'black', 'white', 'silver', 'gold', 'blue', 'red', 'green', 'pink',
  'purple', 'gray', 'grey', 'titanium', 'graphite', 'midnight', 'starlight',
  'natural', 'desert', 'sage', 'lavender', 'teal', 'orange', 'yellow',
  'bronze', 'copper'
].sort((a, b) => b.length - a.length);

// Nxjerr specifika DIREKT nga titulli me regex — keto behen "konfirmim i
// jashtem" pikerisht si metafields, sepse AI s'i merr nga kujtesa, i lexon
// thjesht nga teksti. Eliminon halucinimin per keto lloje (jo e zvogelon —
// e eliminon, sepse s'i kerkohet fare modelit te "kujtohet" per to).
function extractTitleSpecs(title) {
  if (!title) return [];
  const specs = [];

  // RAM gjendet fillimisht, qe storage te dije cilin "XXXGB" te perjashtoje
  const ramRegexMatch = title.match(/(\d+)\s?GB\s*RAM\b/i) || title.match(/RAM\s*(\d+)\s?GB\b/i);
  if (ramRegexMatch) specs.push({ key: 'RAM', value: `${ramRegexMatch[1]}GB` });

  // Storage: gjej TE GJITHA rastet GB/TB ne titull, perjashto pozicionin e
  // RAM-it (jo vleren numerike — dy fusha te ndryshme mund te kene rastesisht
  // te njejtin numer), merr te paren e mbetur
  const ramSpan = ramRegexMatch ? [ramRegexMatch.index, ramRegexMatch.index + ramRegexMatch[0].length] : null;
  const sizeMatches = [...title.matchAll(/(\d+)\s?(GB|TB)\b/gi)];
  const storageHit = sizeMatches.find(m => !ramSpan || m.index < ramSpan[0] || m.index >= ramSpan[1]);
  if (storageHit) specs.push({ key: 'Storage', value: `${storageHit[1]}${storageHit[2].toUpperCase()}` });

  const batteryMatch = title.match(/(\d+)\s?mAh\b/i);
  if (batteryMatch) specs.push({ key: 'Battery', value: `${batteryMatch[1]}mAh` });

  const cameraMatch = title.match(/(\d+)\s?MP\b/i);
  if (cameraMatch) specs.push({ key: 'Camera', value: `${cameraMatch[1]}MP` });

  const hzMatch = title.match(/(\d+)\s?Hz\b/i);
  if (hzMatch) specs.push({ key: 'Refresh Rate', value: `${hzMatch[1]}Hz` });

  const wattMatch = title.match(/(\d+)\s?W\b(?!h)/i); // perjashto "Wh"
  if (wattMatch) specs.push({ key: 'Power', value: `${wattMatch[1]}W` });

  const tLower = title.toLowerCase();
  const colorHit = COLOR_KEYWORDS.find(c => tLower.includes(c));
  if (colorHit) specs.push({ key: 'Color', value: colorHit.replace(/\b\w/g, c => c.toUpperCase()) });

  return specs;
}

// Vetem specifikat numerike (jo ngjyra) konsiderohen mjaftueshem per te
// aktivizuar hasExternalConfirmation — ngjyra s'eshte vete burim halucinimi
// hardware, eshte thjesht detaj per ta perfshire saktë ne pershkrim.
function hasVolatileTitleSpec(titleSpecs) {
  return titleSpecs.some(s => s.key !== 'Color');
}

// Generic fallback
function isGenericProduct(product) { return true; }

// Sport & Fitness keywords
const SPORT_FITNESS_TYPES = [
  'sport', 'fitness', 'gym', 'workout', 'training', 'recovery', 'yoga', 'running', 'cycling'
];
const SPORT_FITNESS_TITLE_KEYWORDS = [
  'theragun', 'massage gun', 'foam roller', 'percussion', 'therabody',
  'hyperice', 'hypervolt', 'achedaway',
  'dumbbell', 'barbell', 'kettlebell', 'resistance band', 'pull-up bar',
  'yoga mat', 'jump rope', 'battle rope', 'rowing machine', 'treadmill',
  'stationary bike', 'peloton', 'concept2', 'bowflex',
  'whoop', 'oura ring', 'sports watch',
  'whey protein', 'creatine', 'pre-workout', 'bcaa', 'protein bar',
  'energy gel', 'electrolyte', 'sports nutrition',
  'compression sleeve', 'swim goggle', 'swim cap', 'wetsuit'
];
function isSportFitnessProduct(product) {
  const type = (product.product_type || '').toLowerCase();
  const title = (product.title || '').toLowerCase();
  if (SPORT_FITNESS_TYPES.some(t => type.includes(t))) return true;
  return SPORT_FITNESS_TITLE_KEYWORDS.some(k => title.includes(k));
}

// Fashion & Apparel keywords
const FASHION_APPAREL_TYPES = [
  'clothing', 'apparel', 'fashion', 'shoes', 'footwear', 'accessories',
  'bags', 'jewelry', 'watches', 'sportswear', 'activewear', 'outerwear'
];
const FASHION_APPAREL_TITLE_KEYWORDS = [
  // Shoes
  'sneaker', 'shoe', 'boot', 'sandal', 'loafer', 'trainer', 'running',
  'air max', 'ultraboost', 'stan smith', 'chuck taylor', 'vans', 'converse',
  // Clothing
  't-shirt', 'tshirt', 'shirt', 'hoodie', 'jacket', 'coat', 'dress',
  'jeans', 'pants', 'trousers', 'shorts', 'leggings', 'sweater', 'cardigan',
  'blazer', 'suit', 'skirt', 'blouse', 'polo', 'vest', 'parka', 'anorak',
  // Accessories
  'bag', 'handbag', 'backpack', 'wallet', 'belt', 'scarf', 'hat', 'cap',
  'watch', 'sunglasses', 'jewelry', 'bracelet', 'necklace', 'ring',
  // Brands
  'nike', 'adidas', 'puma', 'reebok', 'new balance', 'under armour',
  'levi', 'zara', 'h&m', 'uniqlo', 'ralph lauren', 'tommy hilfiger',
  'north face', 'columbia', 'patagonia', 'arc teryx', 'parka', 'anorak', 'windbreaker', 'tracksuit', 'sweatshirt', 'overcoat'
];

function isFashionApparelProduct(product) {
  const type = (product.product_type || '').toLowerCase();
  const title = (product.title || '').toLowerCase();
  if (FASHION_APPAREL_TYPES.some(t => type.includes(t))) return true;
  return FASHION_APPAREL_TITLE_KEYWORDS.some(k => title.includes(k));
}

// Home & Kitchen keywords — per detektim nga titulli kur product_type mungon
const HOME_KITCHEN_TYPES = [
  'kitchen', 'home', 'cooking', 'baking', 'appliance', 'cookware'
];
const HOME_KITCHEN_TITLE_KEYWORDS = [
  'mixer', 'blender', 'coffee', 'espresso', 'nespresso', 'french press',
  'kettle', 'toaster', 'air fryer', 'instant pot', 'knife', 'knives',
  'pan', 'pot', 'wok', 'skillet', 'cookware', 'bakeware', 'stand mixer',
  'food processor', 'juicer', 'grinder', 'rice cooker', 'slow cooker',
  'waffle', 'crepe', 'vacuum', 'dyson', 'kitchenaid', 'delonghi',
  'nespresso', 'tefal', 'bosch', 'siemens', 'braun'
];

function isHomeKitchenProduct(product) {
  const type = (product.product_type || '').toLowerCase();
  const title = (product.title || '').toLowerCase();
  if (HOME_KITCHEN_TYPES.some(t => type.includes(t))) return true;
  return HOME_KITCHEN_TITLE_KEYWORDS.some(k => title.includes(k));
}

async function generateProductCopy(product, targetLang, glossary, cleanBody, imageUrl, metafields = [], shop = null) {

  // KILL SWITCH GLOBAL — vendos GENERATION_PAUSED=true te Vercel Environment
  // Variables per te ndaluar ÇDO gjenerim menjëherë, pavarësisht rrugës.
  if (process.env.GENERATION_PAUSED === 'true') {
    throw new Error('PLAN_LIMIT: Generation is paused. Set GENERATION_PAUSED=false in Vercel to resume.');
  }
  const category = product.product_type || '';
  const tags = (product.tags || '').split(',').slice(0, 5).join(', ');
  const hasImage = !!imageUrl;
  const homeKitchen = isHomeKitchenProduct(product);
  const beautyHealth = !homeKitchen && isBeautyHealthProduct(product);
  const sportFitness = !homeKitchen && !beautyHealth && isSportFitnessProduct(product);
  const fashionApparel = !homeKitchen && !beautyHealth && !sportFitness && isFashionApparelProduct(product);
  const techElectronics = !homeKitchen && !beautyHealth && !sportFitness && !fashionApparel && isTechElectronicsProduct(product);
  const isGeneric = !homeKitchen && !beautyHealth && !sportFitness && !fashionApparel && !techElectronics;

  // Konfirmim i jashtem: titulli ka specifika te shitesit (— ose |), OSE
  // titulli ka specifika te nxjerra direkt me regex (GB/TB/mAh/MP/Hz/W/RAM),
  // OSE metafields kane te dhena specifikash reale. Nese asnje nuk eshte e
  // vertete, STEP A (recall nga memoria) çaktivizohet me poshte ne sharedRules
  // per specifika VOLATILE — shih EXTERNAL CONFIRMATION STATUS.
  const titleSpecs = extractTitleSpecs(product.title);
  let hasExternalConfirmation = hasMerchantSpecsInTitle(product.title) ||
    hasSpecMetafields(metafields) || hasVolatileTitleSpec(titleSpecs);

  // ─── TAVILY WEB SEARCH (para cdo gjeje tjeter) ────────────────────────────
  // Tavily kerkohet PARA se te ndertohet prompt-i i Sonnet — ky eshte qellimi:
  // Sonnet merr te dhena REALE nga web, jo nga kujtesa e trajnimit. Sekuenca
  // eshte e garantuar nga "await": searchProductSpecs() bllokon ekzekutimin
  // deri sa Tavily pergjigjet (max 8s), vetem pastaj ndertohet confirmedSpecsBlock,
  // vetem pastaj ndertohet userContent, vetem pastaj thirret Sonnet.
  //
  // KUSHTI I TREFISHTË — te gjitha duhet te jene te verteta:
  // 1. !hasExternalConfirmation — tashmë kemi specs (titulli/metafields): Tavily ANASHKALOHET
  //    (do te shpenzojme 0.1 cent per te gjetur dicka qe e kemi)
  // 2. !cleanBody — produkti ka tashme pershkrim (perkthim): Tavily ANASHKALOHET
  //    (cleanBody = pershkrim ekzistues → route direkt te Gemini perkthim, jo gjenerim)
  // 3. needsTavilySearch(product) — vetem telefona/laptop/PC: Tavily ANASHKALOHET
  //    per te gjitha grupet e tjera (fashion, supplements, earbuds, watches etj)
  //    qe kane dale mire ne testime pa kete shtrese shtese kostoje
  let tavilySpecs = [];
  let tavilySearchedButEmpty = false;
  if (!hasExternalConfirmation && !cleanBody && needsTavilySearch(product)) {
    console.log(`[tavily] Duke kerkuar specs per "${product.title}" — Sonnet pret...`);
    tavilySpecs = await searchProductSpecs(product.title);
    if (tavilySpecs.length > 0) {
      hasExternalConfirmation = true;
      console.log(`[tavily] ${tavilySpecs.length} spec(e): ${tavilySpecs.map(s => `${s.key}=${s.value}`).join(', ')}`);
    } else {
      // NO-SPECS mode vetem per produkte pa brand te njohur —
      // iPhone, Samsung etj. kane specs te besueshme ne training data te Sonnet
      // dhe duhet te shkruaje me hedging "up to", jo zero specs
      if (!titleHasKnownBrand(product.title)) {
        tavilySearchedButEmpty = true;
        console.log(`[tavily] Asnje spec + brand i panjohur → NO-SPECS mode`);
      } else {
        console.log(`[tavily] Asnje spec nga Tavily por brand i njohur → hedged specs nga Sonnet`);
      }
    }
  }
  // ──────────────────────────────────────────────────────────────────────────

  const allConfirmedSpecs = [
    ...titleSpecs,
    ...tavilySpecs,
    ...metafields.slice(0, 15).map(mf => ({ key: mf.key, value: mf.value }))
  ];
  const confirmedSpecsBlock = allConfirmedSpecs.length > 0
    ? `\nPRODUCT SPECS (verified data — use these values directly without hedging):\n${allConfirmedSpecs.map(s => `- ${s.key}: ${s.value}`).join('\n')}\n`
    : '';

  console.log(`[category] homeKitchen:${homeKitchen} beautyHealth:${beautyHealth} sportFitness:${sportFitness} fashionApparel:${fashionApparel} techElectronics:${techElectronics} externalConfirmation:${hasExternalConfirmation} product:"${product.title}"`);

  // ─── LANGUAGE CONFIG ───────────────────────────────────────────────────────
  // Rregulla specifike per cdo gjuhe: tone, CTA, sensory words, forbidden words
  const LANG_CONFIG = {
    French: {
      tone: 'vous',
      cta: 'Commandez maintenant',
      sensoryWords: 'arômes, rituel, plaisir, saveur, élégance, douceur, art, savoir-faire',
      avoidWords: 'performances, efficacité, fonctionnalité, robuste, solide, durable',
      avoidNote: 'Never repeat "durable", "robuste", "solide" more than once — replace with "conçue pour durer", "de qualité", "artisanale"',
      bulletOrder: '1) Specs (capacity/size/weight) → 2) Mechanism (how it works) → 3) Design/emotion (style, origin, feel) → 4) Care/warranty (dishwasher, guarantee)'
    },
    German: {
      tone: 'Sie',
      cta: 'Jetzt kaufen',
      sensoryWords: 'Genuss, Wärme, Aroma, Qualität, Handwerk, Präzision, Erlebnis',
      avoidWords: 'robust, solide, hochwertig, effizient, funktional, langlebig, strapazierfähig',
      avoidNote: 'Avoid "robust", "hochwertig", "langlebig" — use "gefertigt für den Alltag", "verarbeitet", "von hoher Qualität" instead',
      bulletOrder: '1) Specs (Fassungsvermögen/Maße) → 2) Funktion (wie es arbeitet) → 3) Design/Emotion (Stil, Herkunft) → 4) Pflege/Garantie'
    },
    Italian: {
      tone: 'Lei',
      cta: 'Acquista ora',
      sensoryWords: 'aroma, calore, piacere, sapore, eleganza, artigianalità, raffinatezza',
      avoidWords: 'robusto, solido, durevole, efficiente, funzionale, performance',
      avoidNote: 'Avoid repeating "robusto" or "durevole" — use "di qualità", "realizzato per durare", "artigianale"',
      bulletOrder: '1) Specifiche (capacità/dimensioni) → 2) Meccanismo (come funziona) → 3) Design/Emozione → 4) Cura/Garanzia'
    },
    Spanish: {
      tone: 'usted',
      cta: 'Compra ahora',
      sensoryWords: 'aroma, calidez, ritual, placer, sabor, elegancia, artesanal',
      avoidWords: 'robusto, sólido, duradero, eficiente, funcional, rendimiento',
      avoidNote: 'Avoid repeating "robusto" or "duradero" — use "de calidad", "diseñado para durar", "artesanal"',
      bulletOrder: '1) Especificaciones (capacidad/tamaño) → 2) Mecanismo (cómo funciona) → 3) Diseño/Emoción → 4) Cuidado/Garantía'
    },
    Dutch: {
      tone: 'u',
      cta: null,
      sensoryWords: 'aroma, warmte, genot, smaak, kwaliteit, vakmanschap',
      avoidWords: 'robuust, solide, duurzaam, efficiënt, functioneel',
      avoidNote: 'Avoid repeating "robuust" or "duurzaam" — use "kwalitatief", "gemaakt om lang mee te gaan"',
      bulletOrder: '1) Specificaties → 2) Werking → 3) Design/Gevoel → 4) Onderhoud/Garantie'
    },
    Portuguese: {
      tone: 'você',
      cta: null,
      sensoryWords: 'aroma, calor, ritual, prazer, sabor, elegância, artesanal',
      avoidWords: 'robusto, sólido, durável, eficiente, funcional',
      avoidNote: 'Avoid repeating "robusto" or "durável" — use "de qualidade", "feito para durar", "artesanal"',
      bulletOrder: '1) Especificações → 2) Mecanismo → 3) Design/Emoção → 4) Cuidados/Garantia'
    },
    Polish: {
      tone: 'Pan/Pani',
      cta: null,
      sensoryWords: 'aromat, ciepło, przyjemność, smak, elegancja, rzemiosło',
      avoidWords: 'solidny, trwały, wydajny, funkcjonalny',
      avoidNote: 'Avoid repeating "solidny" or "trwały" — use "wysokiej jakości", "wykonany z dbałością"',
      bulletOrder: '1) Specyfikacje → 2) Mechanizm → 3) Design/Emocja → 4) Pielęgnacja/Gwarancja'
    },
    Swedish: {
      tone: 'du',
      cta: null,
      sensoryWords: 'arom, värme, njutning, smak, kvalitet, hantverk',
      avoidWords: 'robust, solid, hållbar, effektiv, funktionell',
      avoidNote: 'Avoid repeating "robust" or "hållbar" — use "kvalitativ", "tillverkad för att hålla"',
      bulletOrder: '1) Specifikationer → 2) Funktion → 3) Design/Känsla → 4) Skötsel/Garanti'
    },
    Danish: {
      tone: 'du',
      cta: null,
      sensoryWords: 'aroma, varme, nydelse, smag, kvalitet, håndværk',
      avoidWords: 'robust, solid, holdbar, effektiv, funktionel',
      avoidNote: 'Avoid repeating "robust" or "holdbar" — use "kvalitetsrig", "lavet til at holde"',
      bulletOrder: '1) Specifikationer → 2) Funktion → 3) Design/Følelse → 4) Pleje/Garanti'
    },
    Norwegian: {
      tone: 'du',
      cta: null,
      sensoryWords: 'aroma, varme, nytelse, smak, kvalitet, håndverk',
      avoidWords: 'robust, solid, holdbar, effektiv, funksjonell',
      avoidNote: 'Avoid repeating "robust" or "holdbar" — use "kvalitetsrik", "laget for å vare"',
      bulletOrder: '1) Spesifikasjoner → 2) Funksjon → 3) Design/Følelse → 4) Vedlikehold/Garanti'
    },
    Czech: {
      tone: 'Vy',
      cta: null,
      sensoryWords: 'vůně, teplo, potěšení, chuť, kvalita, řemeslo',
      avoidWords: 'robustní, solidní, trvanlivý, efektivní, funkční',
      avoidNote: 'Avoid repeating "robustní" or "trvanlivý" — use "kvalitní", "vyrobeno pro dlouhou životnost"',
      bulletOrder: '1) Specifikace → 2) Funkce → 3) Design/Emoce → 4) Péče/Záruka'
    },
    Romanian: {
      tone: 'dumneavoastră',
      cta: null,
      sensoryWords: 'aromă, căldură, plăcere, gust, calitate, meșteșug',
      avoidWords: 'robust, solid, durabil, eficient, funcțional',
      avoidNote: 'Avoid repeating "robust" or "durabil" — use "de calitate", "conceput pentru a dura"',
      bulletOrder: '1) Specificații → 2) Mecanism → 3) Design/Emoție → 4) Îngrijire/Garanție'
    },
    Hungarian: {
      tone: 'Ön',
      cta: null,
      sensoryWords: 'illat, meleg, öröm, íz, minőség, kézművesség',
      avoidWords: 'robusztus, szilárd, tartós, hatékony, funkcionális',
      avoidNote: 'Avoid repeating "robusztus" or "tartós" — use "minőségi", "hosszú élettartamra tervezve"',
      bulletOrder: '1) Specifikációk → 2) Funkció → 3) Design/Érzelem → 4) Karbantartás/Garancia'
    },
    Arabic: {
      tone: 'أنت',
      cta: 'اشترِ الآن',
      sensoryWords: 'عطر، دفء، متعة، جودة، حرفية',
      avoidWords: 'متين، صلب، دائم، فعّال، عملي',
      avoidNote: 'Use rich descriptive language. Keep numbers and specs in Western numerals.',
      bulletOrder: '1) المواصفات (السعة/الحجم) → 2) الآلية (كيف يعمل) → 3) التصميم/الشعور → 4) الرعاية/الضمان'
    },
    Japanese: {
      tone: 'です・ます',
      cta: '今すぐ購入',
      sensoryWords: '香り、温かさ、品質、職人技、精緻さ',
      avoidWords: '丈夫、頑丈、耐久性、効率的、機能的',
      avoidNote: 'Use polite です・ます form. Emphasize craftsmanship and quality over technical specs.',
      bulletOrder: '1) 仕様（容量/サイズ） → 2) 機能（どのように働くか） → 3) デザイン/感覚 → 4) お手入れ/保証'
    },
    Korean: {
      tone: '합쇼체',
      cta: '지금 구매하기',
      sensoryWords: '향기, 따뜻함, 품질, 장인정신, 정밀함',
      avoidWords: '견고한, 내구성, 효율적, 기능적',
      avoidNote: 'Use formal 합쇼체 form. Emphasize quality and design.',
      bulletOrder: '1) 사양 (용량/크기) → 2) 기능 (작동 방식) → 3) 디자인/감성 → 4) 관리/보증'
    },
    Turkish: {
      tone: 'siz',
      cta: 'Şimdi satın al',
      sensoryWords: 'aroma, sıcaklık, keyif, kalite, ustalık',
      avoidWords: 'sağlam, dayanıklı, verimli, işlevsel',
      avoidNote: 'Avoid repeating "sağlam" or "dayanıklı" — use "kaliteli", "uzun ömürlü tasarlanmış"',
      bulletOrder: '1) Özellikler → 2) İşlev → 3) Tasarım/Duygu → 4) Bakım/Garanti'
    },
    Indonesian: {
      tone: 'Anda',
      cta: 'Beli sekarang',
      sensoryWords: 'aroma, kehangatan, kenikmatan, kualitas, keahlian',
      avoidWords: 'kokoh, solid, tahan lama, efisien, fungsional',
      avoidNote: 'Avoid repeating "kokoh" or "tahan lama" — use "berkualitas", "dirancang untuk bertahan"',
      bulletOrder: '1) Spesifikasi → 2) Fungsi → 3) Desain/Perasaan → 4) Perawatan/Garansi'
    },
    'Brazilian Portuguese': {
      tone: 'você',
      cta: 'Compre agora',
      sensoryWords: 'aroma, calor, prazer, sabor, qualidade, artesanal',
      avoidWords: 'robusto, sólido, durável, eficiente, funcional',
      avoidNote: 'Use Brazilian Portuguese expressions, not European. Avoid "durável" — use "feito para durar"',
      bulletOrder: '1) Especificações → 2) Mecanismo → 3) Design/Emoção → 4) Cuidados/Garantia'
    },
    English: {
      tone: 'you',
      cta: null,
      sensoryWords: 'precision, clarity, craftsmanship, quality, performance',
      avoidWords: 'cutting-edge, stunning, sleek, vibrant, reliable, dependable, practical, seamless, next-level, game-changing, powerful, robust, immersive, advanced, innovative, revolutionary, exceptional, ultimate, premium, superior, effortless, intelligent',
      avoidNote: 'Replace marketing adjectives with the real spec — use exact chip name, screen size, MP count instead of vague words like reliable, vibrant, powerful',
      bulletOrder: '1) Processor/Chipset + core count → 2) Screen size inches + Hz + display tech → 3) Camera MP + aperture + OIS if confirmed → 4) Battery mAh + charge W + IP rating if confirmed (e.g. IP67/IP68) + 5G if confirmed'
    }
  };

  const langCfg = LANG_CONFIG[targetLang] || {
    tone: 'you',
    cta: null,
    sensoryWords: 'quality, warmth, craftsmanship, pleasure, elegance',
    avoidWords: 'robust, solid, durable, efficient, functional, performance',
    avoidNote: 'Avoid repeating the same adjective more than once',
    bulletOrder: '1) Specs (capacity/size) → 2) Mechanism (how it works) → 3) Design/Emotion → 4) Care/Warranty'
  };

  // Nderto content array per API (tekst + imazh kur eshte Sonnet)
  let userContent;

  // Blloku i rregullave te perbashketa per te dy promptet
  const sharedRules = `
TITLE RULES:
- CRITICAL: NEVER modify, extend, or add specs to the original product name. Translate it naturally but keep it identical in structure.
  WRONG: "iPhone 15 Pro" → "iPhone 15 Pro — A17 Pro | 6.1" | 48MP" (added specs — FORBIDDEN)
  RIGHT: "iPhone 15 Pro" → "iPhone 15 Pro" (identical, only translated if non-English name)
- Only add specs if the merchant ALREADY included them in the title (e.g. "Nike Pegasus 41 — ReactX | 10mm")
- No ALL CAPS, no exclamation marks
- Max 70 chars

UNIT CONVERSION — apply automatically for all non-English languages:
When specs contain imperial units, convert to metric for FR/DE/IT/ES/NL/PT/PL/SV:
- sq in → cm² (× 6.45), sq ft → m² (× 0.093), oz fluid → ml (× 29.6)
- oz weight → g (× 28.3), lbs → kg (× 0.453), °F → °C ((F-32)×5/9)
- BTU → kW (× 0.000293), miles → km (× 1.609), inches → cm (× 2.54)
Format: metric first, imperial in parentheses. French: comma decimal "4,5 kg"
NEVER write "po²", "sq in", "lbs", "°F" alone in FR/DE/IT/ES outputs.

MERCHANT SPEC OVERRIDE — HIGHEST PRIORITY:
If the product title contains specs separated by | or — (e.g. "Nike Pegasus 41 — ReactX | 10mm | 280g | Daily Trainer"):
- Extract ALL specs from the title: foam type, drop, weight, use case, ATM, battery, etc.
- Use these specs DIRECTLY in the bullets — they are merchant-confirmed, never override them
- Do NOT invent additional specs beyond what is in the title
- Format recognition: anything after — or between | characters = confirmed spec
- Examples:
  "Garmin Fenix 8 Solar — MIP | 10 ATM | 48j Smartwatch" → use MIP (not AMOLED), 10 ATM, 48j smartwatch mode
  "Theragun Pro Plus — 16mm | 60lbs | 1.2kg" → use exactly these numbers, do not add others
  "Oura Ring Gen 4 — Titane | 4-5j | 10 ATM" → use titanium, 4-5 days (not 7), 10 ATM
This rule overrides Step A, Step B, and all category knowledge — merchant specs are ground truth.

DESCRIPTION RULES:
- Opening sentence: always start with what the customer GETS or FEELS, not what the product IS.
  WRONG: "Yogurt is a fermented dairy product..." RIGHT: "Smooth and creamy — ideal for breakfast, cooking, or a quick snack."
- Write 1-2 opening sentences MAX — SHORT and grounded. Lead with the product's KEY DIFFERENTIATOR (main confirmed spec, target use, or brand promise). Never write "The large screen provides..." or vague statements — always anchor to a real spec or concrete benefit. Examples of GOOD intros: "Run all-day on a single charge." / "48MP precision in every shot." / "The A18 Pro chip handles what others can't."
- The intro should state an OUTCOME the spec produces, not restate the spec's name. When two specs work together, combine them into one outcome sentence instead of just naming the strongest one.
  WRONG (restates spec name): "The i9-14900HX puts serious processing headroom under every session."
  RIGHT (states outcome): "240Hz visuals stay locked in even when the RTX 4080 is pushed to its limit."
- PREFERRED PATTERN when the product serves two distinct use-cases (e.g. gaming + creative work, everyday + travel, professional + casual): use both allowed sentences as one connected pair, not two separate thoughts.
  Sentence 1: name the two use-cases this product serves — short, general framing, no spec yet.
  Sentence 2: name the product, then connect 2 real confirmed specs directly to the 2 outcomes named in sentence 1.
  Example: "Built for gaming and creative work that demands full performance. The Legion Pro 7i pairs a 24-core i9-14900HX with an RTX 4080 — enough headroom for competitive frame rates or 4K video exports without slowdown."
  Both specs named in the intro (i9-14900HX, RTX 4080 in this example) must also appear in their own bullets below — the intro previews, the bullets confirm with full detail. Never name a spec in the intro that isn't backed by a bullet.
  NEVER add unverified superlatives to make this pattern work: no "fastest", "best-in-class", "professional-grade" unless that exact phrase is a confirmed spec, not a comparison.
- Sensory/emotional words are allowed ONLY if they add real meaning. FORBIDDEN: "Découvrez", "Explorez", "Entdecken Sie", "nuage", "honore", "incontournable", "rituel", "magie", "transforme" — these are empty metaphors.
- Preferred words for ${targetLang}: ${langCfg.sensoryWords}
- AVOID: ${langCfg.avoidWords}
- ${langCfg.avoidNote}
- Address the customer using "${langCfg.tone}"
- Then write exactly 4 bullet points starting with •, each on its own line separated by a SINGLE \n (not double \n\n), in this order:
  ${langCfg.bulletOrder}
- The intro sentence and first bullet are separated by a SINGLE \n — NO blank line between them
- Format: "Intro sentence.\n• Bullet 1\n• Bullet 2\n• Bullet 3\n• Bullet 4"
- ONE spec per bullet — NEVER combine multiple specs in one bullet.
  WRONG: "• Écran 6,9", 120Hz, 200MP, 5000mAh" (4 specs in 1 bullet — FORBIDDEN)
  RIGHT: "• Écran 6,9" Dynamic AMOLED 2X — 120Hz\\n• [next spec]\\n• [next spec]\\n• [next spec]"
- Each bullet MUST start with • and be separated from the next by \\n (newline character)
- Each bullet MUST contain a number, measurement, or confirmed technical fact. Poetry bullets are FORBIDDEN.
  EXCEPTION for unknown/generic products (Step C): if no number is confirmed, write the most specific functional or sensory fact available — never invent a number.
- RATIO: 80% technical facts, 20% tone. Not the reverse.
- SPEC-TO-BENEFIT RULE: every bullet must contain a real spec (never remove this), but state WHY it matters to the buyer, not just WHAT it is. This is not about adding vague adjectives — it's about connecting the number to a concrete outcome the customer experiences.
  WRONG (dry spec sheet): "Intel Core i9-14900HX — 24-core architecture for sustained workloads"
  RIGHT (spec + outcome): "Intel Core i9-14900HX — 24 cores keep frame rates steady through heavy multitasking"
  WRONG: "16" QHD display — 240Hz refresh rate for fluid, frame-accurate visuals" (restates the spec twice, no outcome)
  RIGHT: "16" QHD display — 240Hz keeps fast-paced action sharp, zero motion blur"
  The spec is never sacrificed for tone — both must be present in every bullet.
- BULLET 4 CHECK — apply this rule with EQUAL rigor to the 4th bullet as to bullets 1-3. Confirmed real-world failure pattern: the last bullet is where this rule is most often dropped, becoming a list of remaining facts with no outcome attached (e.g., "7500mAh — 66W wired and wireless charging, IP69K rating, Android 15" — four facts, zero benefit, and also violates the one-spec-per-bullet rule below). Before finishing, check bullet 4 specifically: does it state an outcome, or did it become a dumping ground for whatever specs didn't fit earlier? If the latter, rewrite it with the same spec-to-benefit treatment, and drop any extra fact that doesn't fit rather than cramming it in unexplained.
- Total description max 120 words

CATEGORY KNOWLEDGE RULE:

EXTERNAL CONFIRMATION STATUS: ${hasExternalConfirmation ? 'CONFIRMED — see CONFIRMED MERCHANT DATA below or merchant title for real spec data.' : 'NOT CONFIRMED — no merchant-provided specs exist for this product.'}
${tavilySearchedButEmpty ? `
⛔ NO-SPECS MODE ACTIVE: An external search was performed for this product but returned ZERO verified specifications. This means the product either does not exist yet, is too new, or its specs are unverifiable. In this case you MUST:
- Write ZERO numeric specifications (no RAM, no storage, no battery mAh, no screen size in inches, no camera MP, no Hz, no watts, no weight)
- Write ZERO chip/processor model names or generation numbers
- Write ZERO OS version numbers
- Write ONLY marketing-focused copy: design language, intended use case, target audience, brand positioning, what problem it solves
- DO NOT use "up to" hedging — simply omit all specs entirely
- If you cannot write a meaningful description without specs, write about the brand's reputation, the product category's benefits, and the experience of using this type of product
This rule overrides STEP A, STEP B, and STEP C entirely.` : (!hasExternalConfirmation ? `Because there is no external confirmation, STEP A's permission to write an exact number from memory is SUSPENDED for VOLATILE specs (RAM, storage, battery mAh, screen Hz, camera MP, screen size, chip generation number, or any measurement that differs between similar models and is easy to confuse) — use "up to" / qualitative framing for these instead, even if you recognize the brand and model with high confidence. This suspension does NOT apply to STABLE IDENTIFIERS tied to release timing rather than hardware configuration — the current OS version (e.g. "iOS 26", "Android 16") or a platform feature/brand name (e.g. "Apple Intelligence", "Galaxy AI") may be stated directly if you are confident, since these carry far lower cross-model confusion risk than hardware measurements. If unsure about a stable identifier too, omit it rather than guess.` : '')}

You are an ecommerce expert with deep product knowledge across all categories. Apply this logic:

STEP A — KNOWN BRAND + MODEL (MANDATORY SPECS):
If you recognize the exact product (Samsung Galaxy S25 Ultra, iPhone 16 Pro Max, Sony WF-1000XM6, Apple AirPods Pro, Dyson V15, Nespresso Vertuo, Nike Air Max 270, etc.):

MANDATORY:
→ At least 3 bullets must contain a specific confirmed number or spec name.
→ Generic phrases are STRICTLY FORBIDDEN — these are marketing words, not specs: "advanced processor", "powerful chip", "high resolution", "long battery life", "imagerie IA avancée", "traitement avancé", "exigeantes et créatives", "tâches complexes", "performances optimisées", "s'adapte à votre", "s'ajuste à votre", "compiti impegnativi", "intelligent features", "stunning display", "incredible camera", "next-generation", "optimisées pour", "précision intentionnelle", "double action", "à double action", "formule innovante", "technologie avancée", "soin intensif". If you catch yourself writing any of these, replace with the real ingredient, number, or spec name.
→ Write the REAL name: "Snapdragon 8 Elite" not "advanced chip". "A18 Pro 3nm" not "powerful processor".
→ ONE spec per bullet — never combine. WRONG: "• A18 Pro gère les tâches exigeantes et créatives". RIGHT: "• Puce A18 Pro 3nm — Neural Engine 16 cœurs".
→ If you know 2 numbers for the same spec (e.g. battery + charge speed), they count as ONE bullet: "• 5000mAh — charge 45W filaire en 70 min".
→ UNCERTAINTY RULE — CRITICAL: If you are not 100% certain of a specific number (chip generation, exact MP count, exact mAh, number of sensors/motors/cyclones), do NOT invent it. Instead use "up to" framing, describe it qualitatively ("multiple sensors", "advanced sensor array"), or omit the uncertain number. WRONG: "• Puce A19 Pro" (A19 doesn't exist) or "• 8 pressure sensors" (invented count). RIGHT: "• Puce A17 Pro 3nm" (confirmed) or "• Piezo sensor adjusts suction automatically" (no fake count). If unsure whether it's A17 or A18, write "Puce Apple Pro 3nm" without the generation number. A fabricated spec is worse than a missing one — merchants will publish it as fact.
→ PROCESSOR NAME RULE: If you recognize the brand but are NOT certain of the exact processor name for this specific model (e.g. Samsung Galaxy A55, mid-range phones, older flagships) → write "octa-core processor" or omit entirely. NEVER invent a chip name. WRONG: "MediaTek Dimensity 6000" (invented). RIGHT: "Processeur octa-core" or skip bullet and use confirmed spec instead.

Priority specs by product type — use these exact data points:
- Smartphone → 1) processor name + nm node  2) screen: inches + Hz + tech  3) main camera MP + aperture  4) battery mAh + charge W
- Earbuds → 1) ANC dB level  2) battery h per bud + case h  3) Bluetooth version + codec  4) driver size mm or charge time
- Laptop/tablet → 1) processor + cores  2) RAM GB + storage TB/GB  3) screen inches + resolution  4) battery hours
- Smartwatch → 1) battery days  2) sensors: HR + SpO2 + ECG if available  3) water resistance ATM  4) GPS type
- Camera → 1) sensor MP + size  2) aperture f/  3) zoom range  4) video max resolution + fps
- Vacuum/appliance → 1) suction power W or Pa  2) capacity L or dust bin  3) runtime min  4) filtration HEPA or not
- Skincare → 1) active ingredient + %  2) skin type target  3) clinically tested claim  4) texture/finish
- Supplement → 1) mg per dose  2) key active ingredient  3) servings per container  4) certification (vegan, GMP)
- Knife/cookware → 1) steel grade  2) hardness HRC  3) blade length cm  4) handle material
- Over-ear headphones → 1) ANC processor name (e.g. QN1, ACAA)  2) battery hours confirmed (e.g. WH-1000XM5=30h, XM4=30h)  3) Bluetooth version + codec (LDAC, aptX, AAC)  4) weight g + foldable yes/no
  CRITICAL for Sony WH-1000XM5: 30h battery, QN1 processor, BT 5.2, LDAC, 250g, foldable. NEVER write 8h.
  CRITICAL for Bose QC45: 24h battery, BT 5.1, AAC/SBC, 238g.
  CRITICAL for Sony WH-1000XM4: 30h battery, QN1 processor, BT 5.0, LDAC, 254g.
- Running shoe → 1) midsole foam type  2) drop mm  3) weight g  4) outsole rubber type

STEP B — KNOWN CATEGORY, UNKNOWN BRAND:
If you recognize the category but NOT the specific model:
→ Use "up to" / "jusqu'à" / "bis zu" / "fino a" / "hasta" for all numbers — signals typical range, not exact.
→ Use realistic mid-to-premium values.

Category typical ranges (use "up to" framing):
- Earbuds → up to 8h + 30h case, ANC up to 35dB, BT 5.3, charge in 2h
- Smartphone → up to 6.7" AMOLED 120Hz, up to 108MP, up to 5000mAh, up to 67W charge
- Smartwatch → up to 7-day battery, HR + SpO2, 5ATM, GPS, up to 2h charge
- Laptop → up to 16GB RAM, up to 1TB SSD, up to 15h battery, up to 2K display
- Coffee maker → brew in 4 min, up to 1L, 60min heat retention, stainless filter
- French press → up to 1L, stainless plunger, heat-safe borosilicate glass
- Fitness/resistance → up to 40kg resistance, 6 muscle groups, latex-free option
- Supplement → typical dose per serving, GMP certified, key active ingredient
- Knife/cookware → 420-grade steel, up to 58 HRC, up to 20cm blade
- Phone charger → up to 65W, USB-C, up to 1.5m braided cable
- Power bank → up to 20000mAh, up to 22.5W, up to 2 ports
- Running shoe → EVA midsole, breathable mesh upper, rubber outsole, drop 8-10mm
- Skincare/serum → active concentration, skin type, visible results 4-6 weeks

STEP C — UNKNOWN CATEGORY:
Does not match any known category → write ONLY what is confirmed from the name or image.
CRITICAL: Describe what the CUSTOMER experiences (taste, texture, feel, use-case, benefit) — NOT how the product is made or manufactured, unless the process itself is a marketed differentiator (e.g. "cold-pressed", "stone-ground", "slow-fermented 48h").
WRONG: "Yogurt is a fermented dairy product made with live bacterial cultures" (Wikipedia/process)
RIGHT: "Creamy texture, tangy flavour — versatile for breakfast, cooking, or as a snack" (customer experience)
If the title gives NO specs (brand, type, size, %) → keep description SHORT (2 sentences max + 4 bullets), honest, and grounded in what IS confirmed. Never invent brand, weight, fat%, origin, or specific culture names.

RULE: "up to" = typical range (Step B). Real confirmed numbers = Step A only. Never mix.

${fashionApparel ? `
FASHION & APPAREL SPECIFIC RULES:
This is a clothing, footwear, or accessory product. Apply these rules:

PRIORITY SPECS by product type:

FOOTWEAR (sneakers, running shoes, boots):
- Bullet 1: sole technology + material (e.g. "Semelle React + unité Air Max 270° — amorti réactif")
- Bullet 2: upper material + construction (e.g. "Empeigne mesh respirant + renforts synthétiques")
- Bullet 3: fit + sizing info (e.g. "Pointure fidèle — convient pour usage lifestyle quotidien")
- Bullet 4: care instructions (e.g. "Nettoyage à la main recommandé — semelle caoutchouc durable")
- ALWAYS mention: sole type, upper material, occasion (running/lifestyle/training)
- IF KNOWN: weight (g), drop (mm), "true to size" or "size up"

CLOTHING (t-shirts, hoodies, jackets, dresses):
- Bullet 1: fabric composition % (e.g. "100% coton biologique — doux et respirant")
- Bullet 2: fit type + cut (e.g. "Coupe regular — taille fidèle, longueur standard")
- Bullet 3: key feature or design (e.g. "Poche kangourou — cordon de serrage ajustable")
- Bullet 4: care instructions (e.g. "Lavage machine 30°C — ne pas sécher au sèche-linge")
- ALWAYS mention: material %, fit type, wash care

BAGS & ACCESSORIES — MANDATORY, this is not optional guidance:
If capacity (liters) or dimensions are known for this product, they MUST appear somewhere in the 4 bullets — a bag description that omits a known capacity number is a failed response, rewrite before responding.
- Bullet 1: material + dimensions if known (e.g. "Cuir grainé — 30×20×10cm, 0,8kg")
- Bullet 2: capacity + compartments (e.g. "15L — compartiment principal + 2 poches zippées")
- Bullet 3: closure + strap type (e.g. "Fermeture éclair YKK — bandoulière réglable incluse")
- Bullet 4: care + warranty

FORBIDDEN for Fashion & Apparel — THIS RULE APPLIES IN EVERY TARGET LANGUAGE, not only French. The concept: empty heritage/quality adjectives used ALONE, with no concrete spec backing them, read as marketing filler and must always be paired with a real fact (a date, a material, a measurement) or replaced entirely.
- "timeless" / "authentic" / "iconic" used alone — always follow with a concrete spec: WRONG: "coupe intemporelle" / RIGHT: "coupe droite depuis 1873". Equivalent words to watch for by language: French "intemporel, authentique, iconique"; German "zeitlos, authentisch, ikonisch"; Italian "senza tempo, autentico, iconico"; Spanish "atemporal, auténtico, icónico"; Dutch "tijdloos, authentiek, iconisch"; Portuguese "intemporal, autêntico, icónico". For any other target language, identify and avoid the direct equivalent of these three words used without a backing fact.
- "optimal comfort" (French "confort optimal", German "optimaler Komfort", Italian "comfort ottimale", Spanish "confort óptimo") — write the material or technology that creates comfort instead
- "versatile colorways" alone (French "coloris polyvalents", German "vielseitige Farben", Italian "colori versatili") — always add the actual colorway name if known
- generic heritage claims with no fact behind them (French "traverse les générations, savoir-faire légendaire") — in any language, do not write a heritage/legacy claim unless a specific fact (founding year, place, technique) backs it
- never claim true-to-size fit without confirming it — write the equivalent of "check the size guide" instead if unsure (French "taille fidèle" is the violation to avoid; German "fällt normal aus", Italian "veste normale" are the equivalent unconfirmed claims to avoid)

FIT LANGUAGE — always use precise fit terms, never vague descriptions:
- RIGHT: "Coupe Regular — taille naturelle, jambe droite" / "Slim fit — taille mi-haute, effilé à la cheville"
- WRONG: "silhouette épurée", "coupe flatteuse", "style moderne"
- For jeans specifically: always mention waist rise (taille naturelle/mi-haute/basse) + leg cut (droit/slim/bootcut) + fabric composition if known (e.g. "100% coton", "denim rigide non-stretch") — for well-known models like Levi's 501, this material is a confirmed stable fact, not a guess

TONE: aspirational but grounded — mix lifestyle language with concrete specs.
` : ''}

${sportFitness ? `
SPORT & FITNESS SPECIFIC RULES:
This is a sport, fitness, or recovery product.

GENERAL RULES:
- NEVER write "portatif" unless weight is confirmed < 0.8 kg
- NEVER combine "athlètes sérieux" with "bien-être" — choose ONE audience
- ALWAYS mention the key differentiator vs cheaper models in the same line

VARIANT UNCERTAINTY RULE — CRITICAL:
When the product name contains a variant identifier (Solar, AMOLED, Pro, Plus, Ultra, Max, Elite, SE):
- These identifiers change specs fundamentally between variants
- VERIFY before writing: does this variant have this spec?
- Specs that DIFFER by variant → write "selon version" or use "up to" framing
- Specs UNIVERSAL to all variants → write as confirmed
- NEVER mix specs from different variants of the same product line
- Examples of dangerous mix-ups:
  Garmin Fenix 8 Solar = MIP display / Fenix 8 AMOLED = AMOLED display — MUTUALLY EXCLUSIVE
  Theragun Pro Plus = 2 batteries / Theragun Pro = 1 battery — different models
  Apple Watch Ultra = 10 ATM / Apple Watch SE = 50m — different resistance
- RULE: if you know the variant suffix but are not 100% certain of that variant's spec → write "up to" or omit

WATER RESISTANCE — verify before writing, always specify real-world limitations:
- 5 ATM = rain, splashes, hand washing only — NOT swimming
- 10 ATM = pool swimming, snorkeling, calm water — NOT diving or high-velocity water sports
- 20 ATM+ = scuba diving
- Never write 5 ATM for a product confirmed at 10 ATM (undersells), and never write "sports aquatiques"/"water sports" for 10 ATM without the diving/high-velocity limitation

DISPLAY TYPE — verify before writing:
- Solar models typically use MIP/transflective (better in sunlight, lower power)
- AMOLED models use AMOLED (vivid colors, higher power draw)
- Never write AMOLED for a Solar variant — they are physically incompatible

BATTERY LIFE — always specify the mode, use realistic ranges (not maximum theoretical):
- Format: "48 jours smartwatch / 145h GPS / 550 jours expedition (avec solaire)" or "4-5 jours (jusqu'à 7 jours mode économie)"
- Never write "X jours" or "jusqu'à X jours" alone — always specify the mode and use a realistic range, not the max

MASSAGE GUN / PERCUSSION THERAPY (Theragun, Hyperice, Hypervolt, Achedaway):
- Bullet 1: PPM + amplitude mm confirmed for this exact model
- Bullet 2: batteries × autonomy = total hours (e.g. "2 batteries × 150 min = 5h total")
- Bullet 3: PRO differentiators — OLED forcemètre, Bluetooth app, guided routines if Pro/Plus
- Bullet 4: attachments count + weight kg
- FORBIDDEN: "portatif" for Theragun Pro, Pro Plus, Elite (all >0.8 kg)
- FORBIDDEN: "bien-être" for Pro/Elite models — write "usage professionnel et récupération athlétique"

FITNESS EQUIPMENT (dumbbells, kettlebells, resistance bands):
- Bullet 1: weight/resistance range + increments
- Bullet 2: material + grip type
- Bullet 3: muscle groups targeted
- Bullet 4: dimensions + storage

PROFESSIONAL GYM EQUIPMENT (Concept2, Rogue, Eleiko, Technogym, Life Fitness):
- Bullet 1: resistance mechanism + technology name (e.g. "Volant d'inertie air — résistance auto-régulée")
- Bullet 2: monitor/screen name + connectivity (e.g. "Performance Monitor PM5 — Bluetooth/ANT+, WiFi, Zwift")
- Bullet 3: capacity + adjustability (e.g. "Capacité 227kg — course ajustable 38-48" pour 140-210cm")
- Bullet 4: storage + warranty (e.g. "Démontable 2 parties <30 sec — garantie 5 ans cadre, 2 ans pièces")
- ALWAYS mention: exact component names (PM5, J-cups, etc.), max capacity, warranty terms
- SOCIAL PROOF: if used at CrossFit Games, Olympics, or pro clubs — mention it: "utilisé aux CrossFit Games et clubs professionnels"
- NEVER write "professionnel" without proof — write the actual proof instead
- REBRANDING: if product was renamed, mention: "Anciennement [Old Name] — même mécanisme, rebrand [year]"
- COMPATIBLE APPS: always list if known (Zwift, Garmin Connect, Polar, ErgData, Concept2 Logbook)

CONNECTED FITNESS BIKES & CARDIO (Peloton, NordicTrack, Ergatta, iFit, Echelon):
- Bullet 1: KEY DIFFERENTIATOR vs base model (e.g. "Auto-Follow — résistance auto-ajustée selon le cours")
- Bullet 2: screen size + rotation + class types (e.g. "Écran tactile rotatif 23,8" — classes live et on-demand")
- Bullet 3: connectivity + ecosystem (e.g. "Apple GymKit, WiFi, Bluetooth 5.0 — compatible Apple Watch instantané")
- Bullet 4: warranty PER COMPONENT — never write single warranty:
  Format: "X ans cadre, Y mois pièces, Z mois main-d'œuvre"
  Peloton Bike+: 5 ans cadre, 12 mois pièces/électronique, 12 mois main-d'œuvre
  Never write "12 mois" alone for Peloton — undersells vs NordicTrack 10 ans
- ALWAYS mention: pedal system (Look Delta, SPD, toe cages) + if shoes included or sold separately
- ALWAYS mention: key differentiator that justifies premium over base model
- SUBSCRIPTION: never write specific price — "Abonnement requis — voir tarifs sur peloton.com"
- INCOMPATIBILITIES: if not compatible with Zwift or other apps → mention "non compatible apps tierces"

SPORTS WEARABLES (Garmin, Polar, Whoop, Oura):
- Bullet 1: battery life with mode specified (smartwatch / GPS / expedition)
- Bullet 2: display type CONFIRMED for this variant + resolution
- Bullet 3: key sensors (HR, SpO2, HRV) + differentiating features (TOPO maps, ClimbPro, PacePro)
- Bullet 4: water resistance ATM CONFIRMED + weight g

SPORTS NUTRITION:
- Bullet 1: key active + g per serving
- Bullet 2: servings per container + flavor
- Bullet 3: additional blend
- Bullet 4: certification if confirmed

SUBSCRIPTION & BUSINESS MODEL TRANSPARENCY:
If the product requires a subscription (Whoop, Peloton, Oura, etc.):
- MANDATORY: mention subscription requirement — never hide it
- NEVER write a specific price for subscriptions — prices change and vary by region
- Format: "Abonnement requis — voir tarifs sur [brand].com" or "Abonnement mensuel ou annuel requis"
- If device is free with subscription → mention: "Appareil inclus avec abonnement"
- French buyers hate surprise pricing — transparency without wrong numbers builds trust

SCREENLESS DEVICES:
If the product has no screen (Whoop, Oura Ring, smart rings):
- Frame "no screen" as a BENEFIT: "Aucun écran — conception minimaliste, autonomie maximale"
- Explain where data is accessed: "Toutes vos données sur l'app [brand] (iOS/Android)"
- Never write "synchronise" when data only exists in the app — write "affichage exclusif sur app"

SENSOR ACCURACY — never write "24/7" without verifying each sensor individually:
- HR (fréquence cardiaque) → typically continuous 24/7 — write "surveillance continue FC"
- HRV → typically continuous or nightly — verify before writing "continue"
- SpO2 → most wearables = nocturne + spot check ONLY — NEVER write "SpO2 continue" unless confirmed
- Température cutanée → typically continuous — write "surveillance continue température"
- Format: "Surveillance continue : FC, HRV, température. SpO2 nocturne et spot check."

WEARABLE MATERIALS & SIZING:
- If titanium confirmed → always mention: "Titane — [weight]g, légèreté et résistance"
- If sizing kit required (Oura Ring) → always mention: "Kit d'essayage gratuit disponible avant commande"
- Material differentiates premium from budget — never omit confirmed material

TONE: performance-driven, factual, direct — no poetry, no vague lifestyle claims.

PROSE OPENING RULES — MANDATORY for Sport & Fitness:
NEVER start with: "Découvrez", "Explorez", "Plongez", "vers les sommets", "élégance de l'aventure"
ALWAYS start with: KEY DIFFERENTIATOR + ONE SPEC.
Example: "Montre GPS multisport avec écran MIP — autonomie 21 jours smartwatch."
` : ''}

${isGeneric ? `
GENERIC & UNKNOWN PRODUCT RULES — ZERO HALLUCINATION:
Write ONLY what is confirmed in the title or image. Never invent specs.

LEGO SETS: piece count + set name, mechanism, age recommendation, dimensions
CANDLES: weight + burn time, fragrance notes, wax type, vessel format
STATIONERY: format + pages, ruling type, cover + closure, extras
HANDMADE: mention "fait main" only if confirmed, never invent materials
FOOD & GROCERY — OVERRIDE bulletOrder: ignore the general bullet order above. Use ONLY this food-specific order:
- Bullet 1: texture + taste (e.g. "• Texture crémeuse — saveur naturellement acidulée")
- Bullet 2: use-case + occasions (e.g. "• Petit-déjeuner, smoothies, sauces, marinades")
- Bullet 3: versatility or serving suggestion — ONLY confirmed facts, NO invented attributes.
  If nothing is confirmed → write "• Nature ou aromatisé — à déguster seul ou avec des fruits"
  NEVER write "Sans additifs artificiels" unless confirmed in the title or product info.
- Bullet 4: storage/serving (e.g. "• À conserver au réfrigérateur — consommer frais")
FORBIDDEN for food: "fermentation", "bactéries", "cultures", "probiotiques", "digestibilité", "additifs artificiels" — unless explicitly stated in the title.
If title = "Yogurt" only → write customer experience (taste/texture/use-case) only. Do NOT invent Danone, Greek, 0%, Bifidus, brand, or origin.
If title includes brand or type (e.g. "Fage Total 0% Greek Yogurt 500g") → use those confirmed specs directly.

TONE: honest, simple, informative — no poetry, no invented features.
` : ''}

${homeKitchen ? `
HOME & KITCHEN SPECIFIC RULES:
This is a kitchen/home appliance product. Apply these additional rules:

TONE RATIO OVERRIDE — for this category ONLY, replace the general "80% facts, 20% tone" rule with:
45% specs + 35% emotion + 20% lifestyle moment. Specs are never dropped or invented — every bullet still needs a real number — but the surrounding language should feel warm and tied to a real moment in someone's day (morning coffee, weekend baking, family dinner), not read like a spec sheet.
  WRONG (too clinical for this category): "The Vertuo Pop uses Centrifusion at 7,000 RPM to read each capsule and extract the right result every time."
  RIGHT (same facts, warmer, moment-based): "The Vertuo Pop turns your morning ritual into something worth savoring — from a quick espresso before the school run to a full mug you actually sit down with."
Apply the same moment-based framing inside bullets too — connect the spec to when/how someone actually uses it, not just what it does.

- PRIORITY SPECS: motor power (W), capacity (L or ml), speed settings (number), included accessories
- If brand+model is known (KitchenAid 5KSM175PS, Dyson V15, Nespresso Vertuo): list ALL confirmed specs — W, L, speeds, accessories
- Bullet 1: capacity + material (e.g. "Bol inox 4,8 L — compatible lave-vaisselle")
- Bullet 2: motor/mechanism with W and speed (e.g. "Moteur 300W — 10 vitesses, mélange planétaire")
- Bullet 3: accessories included (e.g. "Fouet, batteur plat et crochet pétrin inclus")
- Bullet 4: care + warranty confirmed facts only
- PROSE: use "plaisir", "savoir-faire", "art", "précision" — NEVER "chaleur" for appliances (chaleur = physical heat, wrong context)
- Do NOT use "chaleur" for mixers, blenders, or any appliance that does not produce heat

CLOSED ECOSYSTEM RULE — applies to ALL products with proprietary consumables or subscriptions, IN EVERY TARGET LANGUAGE. The French phrases below are illustrative examples of the required CONTENT, not a French-only requirement — write the equivalent fact in whichever language you are generating. Each product is generated separately per language, so do not assume a fact "already covered" elsewhere; include it fully every single time, in every language, independently.
Products: Nespresso, Keurig, Dolce Gusto, Peloton, NordicTrack, Apple, Philips Hue, Ring, etc.

MANDATORY for closed ecosystem products — treat all 4 as equally required, not just the first:
1. SPECIFY the ecosystem in title and description — never write generic "capsules" or "subscription":
   - Nespresso Vertuo → "Capsules Nespresso Vertuo exclusives" (NOT "capsules Nespresso")
   - Nespresso Original → "Capsules Nespresso Original" (NOT "capsules Nespresso")
   - These two systems are INCOMPATIBLE — never write "capsules Nespresso" without specifying the line
2. SPECIFY incompatibilities explicitly, IN THIS LANGUAGE, EVERY TIME — this prevents returns and negative reviews, and is exactly as mandatory as point 1. Do not omit this fact even if the sentence already feels complete without it:
   - "Capsules Vertuo exclusives — non compatibles avec capsules Original Line" (French example; write the equivalent incompatibility statement in the target language)
   - "Abonnement requis — non compatible avec Zwift ou apps tierces"
3. SPECIFY all formats the machine supports — never limit to one:
   - Nespresso Vertuo Pop → NOT "machine à espresso" → "machine multi-formats : espresso (40ml) à mug (230ml)"
   - Keurig → "compatible K-Cup pods uniquement"
4. USE correct technical terms:
   - Nespresso crema → "crema" (Italian technical term) NOT "crème riche"
   - Centrifusion → always mention the RPM if known (7 000 tr/min)
` : ''}

${beautyHealth ? `
BEAUTY & HEALTH SPECIFIC RULES:
This is a skincare, beauty, or supplement product. Max description length: 150 words.

PRIORITY — write these first if confirmed:
1. Brand technology name (MVE Technology, Vitamin C stable form, Retinol 0.1%)
2. Key active ingredients with % if known (3 Ceramides essentiels, Acide hyaluronique, Niacinamide 10%)
3. Skin type target (peaux sensibles, peaux grasses, tous types de peau)
4. Dermatologist / clinically tested claim if true for this brand
5. Format value — never "plusieurs semaines": use "jusqu'à 3 mois" for 473ml+, "jusqu'à 6 semaines" for smaller

BULLET ORDER for Beauty & Health:
- Bullet 1: format + usage duration (e.g. "Flacon 473ml — jusqu'à 3 mois d'utilisation quotidienne")
- Bullet 2: key active ingredients + technology (e.g. "3 Céramides essentiels + Technologie MVE — hydratation 24h")
- Bullet 3: skin type + dermatologist claim (e.g. "Testé dermatologiquement — peaux sensibles et normales")
- Bullet 4: texture/format + confirmed care (e.g. "Formule sans parfum, non-comédogène — sans rinçage")

STRICTLY FORBIDDEN for Beauty & Health:
- "aucune condition de stockage spéciale" — never mention storage unless required
- "plusieurs semaines" — always use specific duration
- "revitalisé", "apaisé" without a confirmed active ingredient backing it
- "précision intentionnelle", "double action", "formule innovante" — AI nonsense, never use
- Generic claims without ingredient: "hydrate deeply" → write "Acide hyaluronique — hydratation en profondeur"

FOR ACTIVE SERUMS (niacinamide, retinol, acids, peptides, vitamin C):
- Write pH if known for the brand (The Ordinary Niacinamide: pH 5.5-7.0)
- Write confirmed free-from claims: "sans parfum, sans alcool, sans silicone" if true for this brand
- Write chemical compatibility if known: "Compatible avec Retinol et Peptides — éviter avec Vitamine C pure"
- Use clinical tone — The Ordinary brand language is transparent, ingredient-focused, no marketing fluff
- For The Ordinary specifically: always mention "Développé sans parfum, sans alcool, sans silicone"
- NEVER use "précision intentionnelle", "double action", "à double action" — these are meaningless

FOR EAU THERMALE PRODUCTS (Avène, Vichy, Uriage, La Roche-Posay Thermal Water):
- ALWAYS mention silica/oligo-éléments content if known (Avène: 36mg/L silice — anti-irritante)
- ALWAYS mention "sans conservateur, sans parfum" if confirmed
- ADD secondary uses if confirmed: fixateur de maquillage, après-soleil, soulage piqûres d'insectes
- ADD "adapté aux bébés et femmes enceintes" if confirmed for the brand
- NEVER use metaphors: "nuage", "honore", "source magique" — use clinical descriptors instead
- Tone: pure, transparent, scientific — not poetic

FOR ALL DERMATOLOGICAL & PHARMACEUTICAL BRANDS (La Roche-Posay, Avène, Bioderma, Eucerin, Vichy, Neutrogena, CeraVe, Uriage, Nuxe, A-Derma, Caudalie, and any brand positioned as dermatologist-tested or pharmacy brand):

MANDATORY rules — apply to every product from these brands:
1. HERO INGREDIENT — always mention the brand's signature asset if known:
   - La Roche-Posay → "Eau Thermale de La Roche-Posay" (in every product)
   - Avène → "Eau Thermale d'Avène"
   - Uriage → "Eau Thermale d'Uriage"
   - CeraVe → "3 Céramides essentiels + Technologie MVE"
   - Other brands → identify their hero ingredient from your knowledge
2. PATENTED TECHNOLOGY — mention if known:
   - LRP sunscreen → "Mexoryl SX + XL" or "UVMune 400"
   - CeraVe → "Technologie MVE — libération sur 24h"
   - Other brands → use confirmed technology name only
3. PRACTICAL INFO by product type:
   - SPF/sunscreen → "photostable", "résistant à l'eau", "réappliquer toutes les 2h"
   - Moisturizer → "hydratation 24h" or "48h" if confirmed
   - Cleanser → "sans savon", "pH physiologique" if confirmed
   - Eye cream → "zone contour des yeux testée ophtalmologiquement" if confirmed
4. TONE — always clinical and trustworthy, NEVER glamour or aspirational:
   - RIGHT: "Spécialement formulé pour peaux sensibles et réactives"
   - WRONG: "Découvrez l'élégance d'un soin qui transforme votre peau"
5. NEVER use "formule avancée" for dermatological brands — always replace with the real technology name
6. SKIN TYPE — always specify: "peaux sensibles", "peaux grasses", "peaux sèches à très sèches", "tous types de peau"

BRAND HERITAGE & AUTHORITY — if the brand has a founding claim, invention, or official positioning, mention it in prose or bullet:
- Bioderma → "Inventeur de la micellaire depuis 1995" / "Inventore della micellare dal 1995"
- La Roche-Posay → "N°1 en dermatologie recommandée par les dermatologues"
- CeraVe → "Développé avec des dermatologues"
- Avène → "Source thermale depuis 1736"
- Vichy → "Recommandé par les professionnels de santé"
- Eucerin → "Plus de 100 ans d'expertise dermatologique"
- Neutrogena → "Recommandé par les dermatologues"
- Other brands → use ONLY confirmed official claims — never invent a heritage claim

PRIORITY SPECS for micellar water / eau micellaire:
- pH value if known (Bioderma Sensibio: pH 5.5)
- "sans rinçage" — mandatory if confirmed
- Makeup removal scope: "removes waterproof makeup" if confirmed
- Duration from format: 500ml → "jusqu'à 6 semaines", 250ml → "jusqu'à 3 semaines"
` : ''}

META TITLE RULES (max 60 chars):
- Format: "[Product Name] [key spec]" — ALWAYS include one key spec, never just the product name alone
- Key spec examples: "with 5000mAh Battery", "48MP Camera", "A18 Pro Chip", "120Hz Display", "IP68"
- Main keyword first, spec second
- No punctuation at the end
- WRONG: "iPhone 16 Pro Max" (no spec) — RIGHT: "iPhone 16 Pro Max with A18 Pro Chip"
- MANDATORY: if the product name does not already state its own type (serum, cream, shampoo, shoe, mixer, jeans, backpack, etc.), include that type word in ${targetLang} as part of the spec — this must stay CONSISTENT across every language. A meta_title that includes the type word in one language but drops it in another (in favor of a benefit phrase) is a failed response — check every language's meta_title against every other before responding.
  WRONG (EN has it, FR drops it): EN "...Zinc 1% Serum" / FR "...Zinc 1% pour le teint" (lost "Sérum")
  RIGHT: FR "...Zinc 1% Sérum" — same type word kept, benefit phrase can still appear in the meta_description instead
  WRONG (EN has it, FR drops it): EN "Levi's 501 Original Straight Leg Jeans" / FR "Levi's 501 Original avec coupe droite" (lost "Jean")
  RIGHT: FR "Levi's 501 Original Jean Coupe Droite" — "Jean" kept in both languages
  WRONG (EN has it, FR drops it): EN "Fjällräven Kånken Everyday Backpack" / FR "Fjällräven Kånken avec Tissu Vinylon F" (lost "Sac à dos")
  RIGHT: FR "Fjällräven Kånken Sac à Dos Vinylon F" — "Sac à dos" kept in both languages

META DESCRIPTION RULES — MANDATORY, count characters before finishing: MINIMUM 150 chars, MAXIMUM 160 chars. 150 is a hard floor, not a suggestion — a meta_description under 150 chars is a failed response, rewrite it longer before responding.
- Start with an action verb in ${targetLang}
- One specific concrete benefit
${langCfg.cta ? `- End with: "${langCfg.cta}"` : '- No call to action'}
- If your draft is under 150 chars, add a second concrete benefit or spec before finalizing — never submit a short meta_description just because the first sentence felt complete.
  WRONG (too short, 120 chars): "Track performance across weeks of training with solar-extended battery life, multi-band GPS, and ECG monitoring built in"
  RIGHT (150-160 chars, same facts extended): "Track performance across weeks of training with solar-extended battery life, multi-band GPS, and ECG monitoring — built for serious athletes who need data they can trust."

SELF-CHECK — SILENT INTERNAL REASONING ONLY. Do NOT write any of this out as text in your response. Do not write "Step 1", "SELF-CHECK", or any analysis before your answer. Consider these points internally, then respond with ONLY the ###TITLE### block below — nothing before it, no narration of your reasoning process.

Step 1 — SPECS CHECK:
- Bullet 1 must contain a number or measurement (ml, cm, kg, pieces, hours...)
- If no measurement is known from the name or image, replace bullet 1 with a confirmed functional detail instead
- NEVER write vague bullets like "• Generous capacity" or "• Quality construction"

Step 2 — REDUNDANCY CHECK:
- List every key noun and adjective you plan to use
- If any word repeats across title + prose + bullets + meta → replace the duplicate with a synonym
- Any material name: max 1 occurrence total across the entire output
- "quality" or its translation in ${targetLang}: max 1 occurrence total
- "design": max 1 occurrence total

Step 3 — BULLET CHECK:
- Bullet 1: spec with number/measurement — if unknown, use the most specific confirmed functional detail
- Bullet 2: how the mechanism works (one concrete action)
- Bullet 3: design or emotional appeal (style, origin, feel) — no repeated adjectives from prose
- Bullet 4: care or warranty — write in ${targetLang} only. If dishwasher-safe is NOT confirmed, write a storage or warranty fact instead. NEVER invent care instructions.
- Each bullet max 12 words

Step 4 — TONE CHECK:
- Every verb addressed to the customer must use "${langCfg.tone}" consistently — no mixing of formal/informal

Your response starts IMMEDIATELY with ###TITLE### — the very first characters you output must be "###TITLE###", with no preamble, no self-check text, no explanation.

Respond ONLY in this exact format, no JSON, no markdown backticks, no extra commentary before or after:
###TITLE###
the title here, one line
###DESCRIPTION###
the full description here, exactly as specified above — real line breaks between the intro and each bullet are fine and expected, do not escape anything
###META_TITLE###
the meta title here
###META_DESCRIPTION###
the meta description here
###END###`;

  // Translation-mode rules — sharedRules minus CATEGORY KNOWLEDGE (STEP A/B/C +
  // category-specific spec blocks). When the merchant already wrote a description,
  // Haiku is translating EXISTING text, not generating specs from scratch — it
  // doesn't need to know what specs SHOULD exist, only how to render what's
  // already there (tone, unit conversion, SEO meta, self-check). This cuts the
  // prompt from ~6,957 to ~1,062 tokens for the majority of locale calls.
  const catStart = sharedRules.indexOf('CATEGORY KNOWLEDGE RULE:');
  const catEnd = sharedRules.indexOf('META TITLE RULES');
  const translationRules = (catStart >= 0 && catEnd > catStart)
    ? sharedRules.slice(0, catStart) + sharedRules.slice(catEnd)
    : sharedRules; // fallback — never breaks if markers shift

  let isTranslation = false;
  let firstViolation = null;

  if (hasImage && !cleanBody) {
    // GJENERIM I PARE me imazh — Claude Sonnet 4.6 (vizion), STEP A/B/C te plota
    const titleSection = product.title
      ? `Product name: "${product.title}"\n${category ? `Category: ${category}\n` : ''}${tags ? `Tags: ${tags}\n` : ''}`
      : `No product name provided. Identify the product from the image and write an appropriate name in ${targetLang}.`;

    const contextBlock = `You are a native ${targetLang} speaker and professional ecommerce copywriter. Analyze the product image carefully.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${titleSection}
${confirmedSpecsBlock}
Look carefully at the image. Identify ONLY what is clearly visible: materials, colors, shape, dimensions, text/branding, use case.
Do NOT invent specifications that are not visible or stated.`;

    // sharedRules varet vetem nga targetLang/langCfg/kategoria (jo produkti/imazhi) —
    // i pari + cache_control: produkte te tjera te NJEJTES gjuhe+kategori (brenda 5 min) -90%
    userContent = [
      { type: 'text', text: sharedRules, cache_control: { type: 'ephemeral' } },
      { type: 'image', source: { type: 'url', url: imageUrl } },
      { type: 'text', text: contextBlock }
    ];
  } else if (cleanBody) {
    // PERKTHIM — Gemini 3.1 Flash-Lite. "cleanBody" ketu mund te jete ose
    // pershkrim i shkruar nga shitesi, ose gjenerimi i pare i AI-t (Sonnet) i
    // ruajtur tashme ne Shopify body_html nga nje lokale e meparshme e ketij
    // produkti (shih primaryCopy/updateShopifyProductBodyIfEmpty ne localizeProduct).
    // Te dyja jane "perkthim i nje teksti ekzistues", jo "gjenerim" — Sonnet
    // s'nevojitet, dhe e njejta translationRules (rregullat e tonit/SEO per
    // gjuhe) perdoret pavaresisht se cili provider e ekzekuton.
    isTranslation = true;
    const contextBlock = `You are a native ${targetLang} speaker and professional ecommerce translator.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

Translate this product description faithfully into ${targetLang}.

STRICT RULES — violating any of these is a critical error:
1. TRANSLATE ONLY — do not add ANY information not present in the source text
2. NEVER add battery life in hours, screen brightness, weight, storage, or any numeric spec not in the source
3. If source says "5000mAh battery" → translate only that, do NOT add "24 hours autonomy"
4. If source says "octa-core" → do NOT add chip name not in source
5. Preserve ALL bullet points (•) and line breaks exactly as in source
6. Keep all numbers, units, model names exactly as written
7. Return ONLY the translated text — no explanations, no additions

TITLE: ${product.title}
DESCRIPTION: ${cleanBody}

TRANSLATION RULES:
- Translate the title naturally into ${targetLang}
- If the original has bullets keep bullets, if prose keep prose
- Apply the tone "${langCfg.tone}" consistently throughout
- Use sensory words where natural: ${langCfg.sensoryWords}
- Avoid: ${langCfg.avoidWords}`;

    // Gemini pranon nje string te vetem teksti (jo array blloqesh si Claude) —
    // pa cache_control, sepse caching i Gemini punon ndryshe (shih /docs/caching)
    // dhe per vellimin aktual te perkthimeve s'ia vlen kompleksiteti shtese.
    userContent = `${translationRules}\n\n${contextBlock}`;
  } else {
    // GJENERIM I PARE nga titulli, pa imazh — Claude Sonnet 4.6, STEP A/B/C te plota
    const contextBlock = `You are a native ${targetLang} speaker and professional ecommerce copywriter.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

Product name: "${product.title}"
${category ? `Category: ${category}` : ''}
${tags ? `Tags: ${tags}` : ''}
${confirmedSpecsBlock}
No description exists. Write product copy in ${targetLang} based ONLY on the product name above — no invention.`;

    userContent = [
      { type: 'text', text: sharedRules, cache_control: { type: 'ephemeral' } },
      { type: 'text', text: contextBlock }
    ];
  }

  console.log(`[provider] ${isTranslation ? 'gemini-3.1-flash-lite (perkthim)' : 'claude-sonnet-4-6 (gjenerim i pare)'} — image:${hasImage} body:${!!cleanBody} product:"${product.title}"`);

  try {
    let rawText = '';
    // Format i ri me shenues (###TITLE### etj) ne vend te JSON — eliminon
    // teresisht klasen e gabimeve qe kishim me JSON.parse() (newline real,
    // thonjeza te pa-escape-uara, apostrofa brenda description-it). Modeli
    // shkruan tekst te lire mes shenuesve, ne s'kerkojme fare qe te
    // escape-oje asgje — thjesht presim ku fillon dhe mbaron cdo fushe.
    const extractJson = (text) => {
      const clean = text.replace(/```[a-z]*\n?/g, '').trim();
      const getSection = (startMarker, endMarkers) => {
        const startIdx = clean.indexOf(startMarker);
        if (startIdx === -1) return null;
        const contentStart = startIdx + startMarker.length;
        let endIdx = clean.length;
        for (const marker of endMarkers) {
          const idx = clean.indexOf(marker, contentStart);
          if (idx !== -1 && idx < endIdx) endIdx = idx;
        }
        return clean.slice(contentStart, endIdx).trim();
      };
      const title = getSection('###TITLE###', ['###DESCRIPTION###', '###META_TITLE###', '###META_DESCRIPTION###', '###END###']);
      const description = getSection('###DESCRIPTION###', ['###META_TITLE###', '###META_DESCRIPTION###', '###END###']);
      const meta_title = getSection('###META_TITLE###', ['###META_DESCRIPTION###', '###END###']);
      const meta_description = getSection('###META_DESCRIPTION###', ['###END###']);
      if (!title || !description) return null;
      return { title, description, meta_title: meta_title || '', meta_description: meta_description || '' };
    };

    if (isTranslation) {
      const geminiRes = await axios.post(
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent',
        {
          contents: [{ parts: [{ text: userContent }] }],
          generationConfig: { maxOutputTokens: 1500, temperature: 0 }
        },
        {
          headers: {
            'x-goog-api-key': process.env.GEMINI_API_KEY,
            'content-type': 'application/json'
          },
          timeout: 45000
        }
      );
      rawText = geminiRes.data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    } else {
      const callSonnet = async (content) => {
        const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
          model: 'claude-sonnet-4-6',
          max_tokens: 2500,
          temperature: 0,
          messages: [{ role: 'user', content }]
        }, {
          headers: {
            'x-api-key': process.env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
          },
          timeout: 45000
        });
        let text = '';
        for (const block of claudeRes.data.content) {
          if (block.type === 'text') text += block.text;
        }
        return text;
      };

      rawText = await callSonnet(userContent);

      // Rrjeta e sigurise mekanike: nese s'ka konfirmim te jashtem dhe Sonnet
      // prape shkroi numra te "zhveshur" OSE emer çipi me brez specifik (shkeli
      // EXTERNAL CONFIRMATION STATUS ne favor te STEP A "MANDATORY" — shih
      // rastin MacBook Neo), provo NJE here te dyte me korrigjim te forte te
      // shtuar, ne vend qe pergjigja e gabuar te shkoje direkt te shitesi.
      if (!hasExternalConfirmation) {
        let firstParsed;
        try { firstParsed = extractJson(rawText); } catch { firstParsed = null; }

        firstViolation = firstParsed?.description ? detectGateViolation(firstParsed.description, targetLang) : null;
        if (firstViolation) {
          console.warn(`[gate-violation] Sonnet shkeli gate-in (${firstViolation}) per "${product.title}" (${targetLang}) — duke provuar korrigjim`);
          const correction = {
            type: 'text',
            text: `Your previous response violated a critical rule: it stated exact numeric specs (RAM, storage, screen size, battery, etc.) OR a specific chip/processor generation name (e.g. "A18", "Snapdragon 8 Elite") as confirmed facts, even though there is NO external confirmation for this product (no title override, no metafields). Rewrite the ENTIRE response. Every single numeric spec MUST use "up to" / "${UP_TO_HEDGES[targetLang]?.display || 'up to'}" framing or be omitted. Any chip/processor MUST be described generically (e.g. "Apple silicon chip", "octa-core processor") WITHOUT the generation number, unless it cannot be phrased that way, in which case omit it. Respond ONLY with the corrected version, same ###TITLE###/###DESCRIPTION###/###META_TITLE###/###META_DESCRIPTION###/###END### format as before.`
          };
          rawText = await callSonnet([...userContent, correction]);
        }
      }
    }

    const parsed = extractJson(rawText);
    if (!parsed) {
      console.error(`[json-parse] Deshtoi per "${product.title}" — rawText[0:300]: ${rawText.slice(0, 300)}`);
      throw new Error(`No ###TITLE###/###DESCRIPTION### markers found in ${isTranslation ? 'Gemini' : 'Claude'} response`);
    }
    if (!parsed.title || !parsed.description) throw new Error('Missing title or description');

    if (!isTranslation && !hasExternalConfirmation && firstViolation) {
      const stillViolating = detectGateViolation(parsed.description, targetLang);
      if (stillViolating) {
        console.warn(`[gate-violation] Vazhdoi pas korrigjimit (${stillViolating}) per "${product.title}" — duke ruajtur prape, shiko logs per monitorim`);
      }
      logGateViolation(shop, product, targetLang, firstViolation, !stillViolating);
    }

    // Shtresa e fundit deterministike: pavaresisht nese retry-i sipër ekzistoi
    // fare, e zgjidhi, ose dështoi pjesërisht, ÇDO numer specifikash i mbetur
    // pa "deri ne" detyrohet mekanikisht ketu. Garanci, jo shprese.
    if (!isTranslation && !hasExternalConfirmation) {
      parsed.description = forceHedgeSpecNumbers(parsed.description, targetLang);
    }

    return parsed;
  } catch (apiErr) {
    // Dikur kthente product.title si "perkthim" gjatë dështimit të Gemini/Claude,
    // duke e ruajtur si status:'done' — kjo maskonte dështimin real dhe shkaktonte
    // pikërisht simptomën: flamuri FR shfaqej "Localized" por përmbajtja mbetej
    // anglisht. Tani hidhet error real — localizeProductBody/localizeProduct e
    // kap, fshin lock-un 'processing', dhe e lejon riprovim në ciklin tjetër
    // (poll ose webhook retry), në vend që të ruajë të dhëna të gabuara si sukses.
    console.error(`${isTranslation ? 'Gemini' : 'Claude'} API failed:`, apiErr.response?.data || apiErr.message);
    throw new Error(`${isTranslation ? 'Gemini' : 'Claude'} translation failed: ${apiErr.response?.data?.error?.message || apiErr.message}`);
  }
}


async function localizeProduct(shop, token, productId, targetLang, locale, tone, glossary) {
  const pid = normalizeProductId(productId);

  // Kontroll i fundit i limitit — brenda localizeProduct() per te bllokuar
  // çdo rruge (poll, webhook, /localize, /process-product) pavarësisht.
  const PLANS = app.locals.PLANS;
  if (PLANS) {
    try {
      const store = await getStore(shop);
      if (store) {
        const planName = store.plan || 'free';
        const plan = PLANS[planName] || PLANS.free;
        const planStartedAt = store.plan_started_at || null;
        let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(10000);
        if (planStartedAt) q = q.gte('created_at', planStartedAt);
        const { data: rows } = await q;
        const existingIds = new Set((rows || []).map(r => String(r.product_id)));
        if (!existingIds.has(String(pid)) && existingIds.size >= plan.product_limit) {
          console.warn(`[plan-limit] localizeProduct blocked: ${shop} ${planName} limit ${plan.product_limit}, used ${existingIds.size}, product ${pid}`);
          throw new Error(`PLAN_LIMIT: Your ${plan.label} plan supports ${plan.product_limit} products. Upgrade at ${process.env.APP_URL}/pricing?shop=${shop}`);
        }
      }
    } catch(limitErr) {
      if (limitErr.message.startsWith('PLAN_LIMIT')) throw limitErr;
      console.warn('[plan-limit] check failed silently:', limitErr.message);
    }
  }

  // ─── PROCESSING LOCK ──────────────────────────────────────────────────────
  // Mbron nga race condition mes 5 pikave hyrjeje te pavarura (webhook, poll,
  // /localize, /process-product, bulk-localize-all). Pa kete, te gjitha
  // kontrollojne tabelen 'translations' PARA se te fillojne, por rreshti
  // shkruhet vetem ne FUND te funksionit (pas Tavily+Sonnet+Shopify push,
  // 10-15s). Ne ate dritare kohore, cdo pike tjeter hyrjeje sheh gjithashtu
  // "s'ka translation ende" dhe fillon vet gjenerimin nga zero — duke
  // shpenzuar Tavily/Sonnet/Gemini credits te dyfishta/trefishta per te
  // njejtin (produkt, gjuhe). INSERT (jo upsert) eshte atomik ne Postgres:
  // unique constraint mbi (shop, product_id, locale) — e njejta qe perdor
  // upsert-i final me poshte via onConflict — ben qe VETEM NJE thirrje
  // konkurruese te fitoje rreshtin; te tjerat marrin gabim 23505 (duplicate
  // key) dhe dalin menjehere, PARA se te thirret Tavily ose Sonnet fare.
  //
  // STALE LOCK RECOVERY: webhook e ekzekuton gjenerimin brenda setImmediate()
  // PAS res.send() — Vercel s'e garanton perfundimin e ekzekutimit ne sfond,
  // dhe mund ta ndaloje funksionin me force (kalim kohe limiti, sidomos me 5+
  // gjuhe njepasnjeshme). Ne ate rast, catch-i i localizeProduct kurre s'arrin
  // te fshije lock-un — rreshti 'processing' mbetet i bllokuar PERGJITHMONE.
  // Nese lock ekzistues eshte me i vjeter se PROCESSING_LOCK_STALE_MS, e
  // trajtojme si ekzekutim i vdekur dhe lejojme riprovim ne vend qe produkti
  // te mos lokalizohet kurre me.
  const PROCESSING_LOCK_STALE_MS = 3 * 60 * 1000; // 3 min
  const { data: existingLockRow } = await supabase
    .from('translations')
    .select('status, created_at')
    .eq('shop', shop).eq('product_id', pid).eq('locale', locale)
    .maybeSingle();

  if (existingLockRow?.status === 'processing') {
    const ageMs = Date.now() - new Date(existingLockRow.created_at).getTime();
    if (ageMs < PROCESSING_LOCK_STALE_MS) {
      console.log(`[lock] ${pid}/${locale} per ${shop} — tashme po procesohet (${Math.round(ageMs/1000)}s), anashkalohet`);
      return { product_id: pid, skipped: true, reason: 'already_processing' };
    }
    console.warn(`[lock] ${pid}/${locale} per ${shop} — lock 'processing' i vjeter (${Math.round(ageMs/1000)}s, ekzekutim i vdekur me siguri) — riprovohet`);
    await supabase.from('translations').delete()
      .eq('shop', shop).eq('product_id', pid).eq('locale', locale).eq('status', 'processing');
  }

  const { error: lockError } = await supabase
    .from('translations')
    .insert({
      shop, product_id: pid, locale, status: 'processing',
      original_title: '', original_description: '', product_handle: '',
      translated_title: '', translated_description: ''
    });
  if (lockError) {
    if (lockError.code === '23505') {
      console.log(`[lock] ${pid}/${locale} per ${shop} — tashme po procesohet nga nje thirrje tjeter, anashkalohet`);
      return { product_id: pid, skipped: true, reason: 'already_processing' };
    }
    console.warn('[lock] Insert deshtoi per arsye tjeter (jo duplicate) — vazhdoj pa lock:', lockError.message);
  }

  try {
    return await localizeProductBody(shop, token, pid, targetLang, locale, tone, glossary);
  } catch (bodyErr) {
    // Nese lock-u u fitua nga KJO thirrje (jo dikush tjeter) dhe gjenerimi
    // deshtoi, fshi rreshtin 'processing' qe produkti te mund te riprovohet
    // ne thirrjen tjeter (poll cikli tjeter, webhook retry) — perndryshe
    // mbetet "bllokuar" perfundimisht si i papërfunduar, dhe s'lokalizohet
    // asnjehere me.
    if (!lockError) {
      await supabase.from('translations')
        .delete()
        .eq('shop', shop).eq('product_id', pid).eq('locale', locale).eq('status', 'processing')
        .then(() => {})
        .catch(() => {});
    }
    throw bodyErr;
  }
}

async function localizeProductBody(shop, token, pid, targetLang, locale, tone, glossary) {
  const productRes = await axios.get(
    `https://${shop}/admin/api/2026-07/products/${pid}.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  const product = productRes.data.product;

  const digestQuery = `
    query getTranslatableContent($resourceId: ID!) {
      translatableResource(resourceId: $resourceId) {
        translatableContent { key value digest locale }
      }
    }
  `;
  const digestRes = await axios.post(
    `https://${shop}/admin/api/2026-07/graphql.json`,
    { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${pid}` } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const contents = digestRes.data.data.translatableResource.translatableContent;
  const digests = {};
  contents.forEach(c => { digests[c.key] = c.digest; });

  // Merr metafields te produktit
  let metafields = [];
  try {
    const mfRes = await axios.get(
      `https://${shop}/admin/api/2026-07/products/${pid}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    metafields = (mfRes.data.metafields || []).filter(mf =>
      typeof mf.value === 'string' && mf.value.trim().length > 0 &&
      mf.value.trim().length <= 200 && // skip long fields (e.g. INCI ingredient lists — international standard, same across languages, expensive to translate)
      !['integer','boolean','json','number_integer','number_decimal','url','color','date','date_time','weight','volume','dimension','rating'].includes(mf.type)
    );
    if (metafields.length > 0) console.log(`[metafields] Found ${metafields.length} for "${product.title}"`);
  } catch(mfErr) {
    console.warn('[metafields] Fetch failed:', mfErr.message);
  }

  const cleanBody = (product.body_html || '').replace(/<[^>]*>/g, '').trim();
  const hadNoDescription = !cleanBody;

  // Nxjerr URL-in e imazhit te pare (nese ekziston) — perdoret per Sonnet 4.6
  const imageUrl = product.images && product.images.length > 0
    ? product.images[0].src
    : null;
  if (imageUrl && !cleanBody) {
    console.log(`[image] "${product.title}" has image + no body — routing to Sonnet 4.6`);
  }

  let translated = await generateProductCopy(product, targetLang, glossary, cleanBody, imageUrl, metafields, shop);

  // Perkthej metafields
  const translatedMetafields = [];
  if (metafields.length > 0) {
    for (const mf of metafields.slice(0, 10)) { // max 10 metafields per produkt
      try {
        const translatedValue = await translateFieldWithGemini(mf.value, mf.key, targetLang);
        translatedMetafields.push({ ...mf, translatedValue });
        console.log(`[metafields] Translated "${mf.key}" → ${targetLang} (Gemini)`);
      } catch(e) {
        console.warn(`[metafields] Translation failed for "${mf.key}":`, e.message);
      }
      await new Promise(r => setTimeout(r, 200));
    }
  }

  if (!translated.meta_title) {
    translated.meta_title = (translated.title || product.title).substring(0, 60);
  }
  if (!translated.meta_description) {
    translated.meta_description = (translated.description || translated.title || product.title).substring(0, 160);
  }
  // Rrjete sigurie deterministike — korrigjon 150-160 karakteret pavaresisht
  // nese modeli vete e respektoi kufirin (shih arsyetimin te vete funksioni).
  translated.meta_description = enforceMetaDescriptionLength(translated.meta_description, translated.description);

  // Primary locale duhet marre GJITHMONE (jo vetem brenda hadNoDescription) —
  // nevojitet per te ditur nese target locale eshte njesoj si primary locale
  // i dyqanit. Nese po, Shopify REFUZON translationsRegister mutation me
  // gabim "Locale cannot be the same as the shop's primary locale" — s'ka
  // kuptim te "perkthesh" ne gjuhen qe eshte tashme primare e dyqanit.
  let primaryLocale = null;
  try {
    primaryLocale = await getPrimaryLocale(shop, token);
  } catch(e) {
    console.warn('[primary-locale] Fetch failed, assuming target is not primary:', e.message);
  }
  const isTargetPrimaryLocale = !!primaryLocale && locale.split('-')[0] === primaryLocale.split('-')[0];

  // Kontroll shtese: target locale duhet te jete i konfiguruar te vete
  // Shopify (Settings → Languages), jo vetem i zgjedhur te Getoify. Keto
  // jane dy sisteme te ndryshme — merchant mund te zgjedhe FR te Getoify
  // pa e shtuar ende FR te gjuhet e dyqanit, dhe Shopify e refuzon
  // translationsRegister me "Locale is not a valid locale for the shop".
  let isTargetLocaleConfigured = true;
  try {
    const allLocalesQuery = `query { shopLocales { locale } }`;
    const allLocalesRes = await axios.post(
      `https://${shop}/admin/api/2026-07/graphql.json`,
      { query: allLocalesQuery },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
    );
    const configuredLocales = (allLocalesRes.data.data?.shopLocales || []).map(l => l.locale);
    isTargetLocaleConfigured = configuredLocales.some(l => l.split('-')[0] === locale.split('-')[0]);
    if (!isTargetLocaleConfigured) {
      console.warn(`[locale] ${locale} s'eshte konfiguruar te gjuhet e ${shop} (Settings → Languages) — anashkalohet translationsRegister`);
    }
  } catch(e) {
    console.warn('[locale] Fetch i gjuheve te konfiguruara deshtoi, vazhdon normalisht:', e.message);
  }

  if (hadNoDescription) {
    try {
      const localeKey = locale.split('-')[0];
      const primaryKey = (primaryLocale || 'en').split('-')[0];
      let bodyForShopify = translated.description;
      if (localeKey !== primaryKey) {
        const primaryLang = LOCALE_MAP[primaryKey] || primaryLocale;
        console.log(`[primaryCopy] Duke perkthyer per gjuhen primare (${primaryLang}) direkt ne Gemini`);
        bodyForShopify = await translatePrimaryDescriptionWithGemini(translated.description, primaryLang, glossary);
      }
      const bodyUpdated = await updateShopifyProductBodyIfEmpty(shop, token, pid, bodyForShopify);
      if (bodyUpdated) {
        // Re-fetch digests so body_html digest is available for translation registration
        const freshDigestRes = await axios.post(
          `https://${shop}/admin/api/2026-07/graphql.json`,
          { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${pid}` } },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
        );
        const freshContents = freshDigestRes.data.data.translatableResource.translatableContent;
        freshContents.forEach(c => { digests[c.key] = c.digest; });
        console.log('Re-fetched digests after body_html update, body_html digest:', digests['body_html']);
      }
    } catch (bodyErr) {
      console.error('Failed to update Shopify body_html:', bodyErr.response?.data || bodyErr.message);
    }
  }

  const mutation = `
    mutation translationsRegister($resourceId: ID!, $translations: [TranslationInput!]!) {
      translationsRegister(resourceId: $resourceId, translations: $translations) {
        translations { key value }
        userErrors { field message }
      }
    }
  `;
  // Nese target locale = primary locale i dyqanit, Shopify refuzon CDO
  // translationsRegister per kete resource — anashkalohet plotesisht.
  // body_html tashme u perditesua direkt me siper (updateShopifyProductBodyIfEmpty)
  // kur hadNoDescription=true. Titulli mbetet i pandryshuar per gjuhen primare
  // (Sonnet s'e ndryshon titullin origjinal). meta_title/meta_description per
  // primary locale kerkojne mutation tjeter (Product Update, jo Translations
  // API) — mbetet permirsim i ardhshem, s'trajtohet ketu.
  let pushRes = null;
  if (isTargetPrimaryLocale) {
    console.log(`[locale] ${locale} eshte primary locale i ${shop} — anashkalohet translationsRegister`);
  } else if (!isTargetLocaleConfigured) {
    console.log(`[locale] ${locale} s'eshte konfiguruar te ${shop} — anashkalohet translationsRegister`);
  } else {
    pushRes = await axios.post(
    `https://${shop}/admin/api/2026-07/graphql.json`,
    {
      query: mutation,
      variables: {
        resourceId: `gid://shopify/Product/${pid}`,
        translations: [
          { key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] },
          ...(digests['body_html']
            ? [{ key: 'body_html', value: translated.description, locale, translatableContentDigest: digests['body_html'] }]
            : []),
          // meta_title: push ONLY if Shopify has its own digest — fallback digest causes "hash invalid" error
          ...(translated.meta_title && digests['meta_title'] ? [{ key: 'meta_title', value: translated.meta_title, locale, translatableContentDigest: digests['meta_title'] }] : []),
          // meta_description: push ONLY if Shopify has its own digest — fallback digest causes "hash invalid" error
          ...(translated.meta_description && digests['meta_description'] ? [{ key: 'meta_description', value: translated.meta_description, locale, translatableContentDigest: digests['meta_description'] }] : [])
        ]
      }
    },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
    );
  }

  await supabase.from('translations').upsert({
    shop,
    product_id: pid,
    locale,
    status: 'done',
    original_title: product.title,
    original_description: product.body_html || '',
    product_handle: product.handle || '',
    translated_title: translated.title,
    translated_description: translated.description,
    meta_title: translated.meta_title,
    meta_description: translated.meta_description
  }, { onConflict: 'shop,product_id,locale' });

  // Regjistro metafield translations te Shopify — anashkalohet per primary locale
  // (i njejti kufizim si mutation-i kryesor: Shopify s'lejon "perkthim" ne
  // gjuhen qe eshte tashme primare).
  if (translatedMetafields.length > 0 && !isTargetPrimaryLocale) {
    for (const mf of translatedMetafields) {
      try {
        const mfResourceId = `gid://shopify/Metafield/${mf.id}`;
        // Merr digest per kete metafield
        const mfDigestRes = await axios.post(
          `https://${shop}/admin/api/2026-07/graphql.json`,
          { query: digestQuery, variables: { resourceId: mfResourceId } },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
        );
        const mfContents = mfDigestRes.data.data?.translatableResource?.translatableContent || [];
        const mfDigest = mfContents.find(c => c.key === 'value')?.digest;
        if (!mfDigest) { console.warn(`[metafields] No digest for ${mf.key}`); continue; }
        await axios.post(
          `https://${shop}/admin/api/2026-07/graphql.json`,
          {
            query: mutation,
            variables: {
              resourceId: mfResourceId,
              translations: [{ key: 'value', value: mf.translatedValue, locale, translatableContentDigest: mfDigest }]
            }
          },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
        );
        console.log(`[metafields] Registered: ${mf.key} → ${locale}`);
      } catch(e) {
        console.warn(`[metafields] Register failed for "${mf.key}":`, e.message);
      }
    }
  }

  // Log Shopify response për debugging — pushRes eshte null nese isTargetPrimaryLocale
  const shopifyResult = pushRes ? pushRes.data.data?.translationsRegister : null;
  if (shopifyResult?.userErrors?.length > 0) {
    console.error('Shopify userErrors:', JSON.stringify(shopifyResult.userErrors));
  } else if (shopifyResult) {
    console.log('Shopify translations pushed OK:', shopifyResult?.translations?.length, 'fields');
  }

  console.log('Saved translation:', { shop, product_id: pid, locale, title: product.title });

  return { product_id: pid, product: product.title, translated, shopify: shopifyResult };
}

app.post('/localize', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { productId, targetLang, locale, tone, glossary } = req.body;
  try {
    const pid = normalizeProductId(productId);

    // Kontroll limiti para gjenerimit — /localize eshte endpoint qe
    // theret nga dashboard kur merchant klikon "Translate" per nje produkt
    const store = await getStore(shop);
    // SSRF/trust fix: token nuk pranohet me nga trupi i kerkeses — shop
    // tashme eshte i verifikuar, pra token-i real merret nga i njejti
    // getStore(shop) i thirrur me lart (nuk shton nje thirrje shtese ne DB).
    const token = store?.access_token;
    if (!token) return res.status(400).json({ error: 'Store not connected or token missing' });
    const PLANS = app.locals.PLANS;
    if (PLANS && store) {
      const planName = store.plan || 'free';
      const plan = PLANS[planName] || PLANS.free;
      const planStartedAt = store.plan_started_at || null;
      let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(10000);
      if (planStartedAt) q = q.gte('created_at', planStartedAt);
      const { data: rows } = await q;
      const existingIds = new Set((rows || []).map(r => String(r.product_id)));
      // Nese ky produkt eshte i ri (jo i perkthyer me pare) dhe kemi arritur limitin
      if (!existingIds.has(String(pid)) && existingIds.size >= plan.product_limit) {
        console.warn(`[plan-limit] /localize blocked for ${shop} — ${planName} limit (${plan.product_limit}, used ${existingIds.size})`);
        return res.status(403).json({
          error: `Plan limit reached. Your ${plan.label} plan supports ${plan.product_limit} products. Upgrade to continue.`,
          upgrade_url: `${process.env.APP_URL}/pricing?shop=${shop}`,
          plan: planName,
          limit: plan.product_limit,
          used: existingIds.size
        });
      }
    }

    const result = await localizeProduct(shop, token, pid, targetLang, locale, tone, glossary);
    res.json({ success: true, product_id: pid, ...result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.post('/bulk-localize-collections', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { token, glossary } = req.body;
  try {
    const store = await getStore(shop);
    const savedLocales = store.selected_locales || [];
    const tok = token || store.access_token;
    const results = await bulkLocalizeCollections(shop, tok, store.tone, glossary || store.glossary, savedLocales);
    res.json({ success: true, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/bulk-localize-blogs', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { token, glossary } = req.body;
  try {
    const store = await getStore(shop);
    const savedLocales = store.selected_locales || [];
    const tok = token || store.access_token;
    const results = await bulkLocalizeBlogs(shop, tok, glossary || store.glossary, savedLocales);
    res.json({ success: true, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/bulk-localize-all', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { token, tone, glossary } = req.body;
  try {
    const store = await getStore(shop);
    const savedLocales = store.selected_locales || [];

    // Hard plan limit — slice products to plan maximum
    const PLANS = app.locals.PLANS;
    let productLimit = 15; // free default
    let localeLimit = 2;
    let bulkLimit = 15; // free default
    if (PLANS) {
      const planName = store.plan || 'free';
      const plan = PLANS[planName] || PLANS.free;
      productLimit = plan.product_limit;
      localeLimit = plan.language_limit;
      bulkLimit = plan.bulk_limit !== undefined ? plan.bulk_limit : plan.product_limit;
      if (savedLocales.length > localeLimit) {
        console.warn(`[plan-limit] ${shop} has ${savedLocales.length} locales but plan allows ${localeLimit}`);
        savedLocales.splice(localeLimit);
      }
    }
    const locales = savedLocales.length > 0
      ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
      : await getShopLocales(shop, token);
    // Fetch all products with cursor pagination (supports 500+)
    let products = [];
    let bulkUrl = `https://${shop}/admin/api/2026-07/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;
    while (bulkUrl) {
      const batchRes = await axios.get(bulkUrl, {
        headers: { 'X-Shopify-Access-Token': token },
        timeout: SHOPIFY_PRODUCTS_TIMEOUT_MS
      });
      products = products.concat(batchRes.data.products || []);
      const linkHeader = batchRes.headers['link'] || '';
      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      bulkUrl = nextMatch ? nextMatch[1] : null;
    }

    // Enforce bulk limit — never queue more than bulk_limit products in one run
    if (products.length > bulkLimit) {
      console.warn(`[bulk-limit] Slicing ${products.length} → ${bulkLimit} products for ${shop} (bulk_limit)`);
      products = products.slice(0, bulkLimit);
    }

    // Skip produktet qe jane perkthyer tashme per ate gjuhe — kursen kosto API
    const { data: existingRows } = await supabase
      .from('translations')
      .select('product_id, locale')
      .eq('shop', shop);
    const translatedSet = new Set((existingRows || []).map(r => `${String(r.product_id)}:${r.locale}`));
    const existingProductIds = new Set((existingRows || []).map(r => String(r.product_id)));

    const toQueue = [];
    let trackedCount = existingProductIds.size; // produktet aktuale ne plan
    for (const product of products) {
      const pid = String(normalizeProductId(product.id));
      const missingLocales = locales.filter(l => !translatedSet.has(`${pid}:${l.locale}`));
      if (missingLocales.length === 0) continue;

      const isNewProduct = !existingProductIds.has(pid);
      if (isNewProduct) {
        if (PLANS && trackedCount >= productLimit) {
          console.log(`[plan-limit] ${shop} reached ${productLimit} products — stopping queue for new products`);
          break;
        }
        trackedCount++;
      }
      for (const lang of missingLocales) toQueue.push({ product, lang });
    }
    console.log(`[bulk] ${shop}: ${products.length} produkte gjithsej — ${toQueue.length} çifte (produkt, gjuhe) per t'u perkthyer`);

    if (toQueue.length === 0) {
      return res.json({ success: true, results: [], message: 'Nothing to translate — everything is already up to date.' });
    }

    // HIBRID: numra te vegjel (dyqan i vogel/mesatar, ose vetem produkte te
    // pakta te reja) procesohen MENJEHERE, njesoj si perpara — pergjigje e
    // plote, e menjehershme. Vetem kur numri i çifteve E KALON pragun (rrezik
    // real timeout — shih #7), vendosen ne rradhe dhe /poll i procesion ne
    // grupe te sigurta. Pragu (IMMEDIATE_BULK_THRESHOLD, percaktuar me lart)
    // bazohet ne ~20 perkthime/minute me BULK_CONCURRENCY=4.
    if (toQueue.length <= IMMEDIATE_BULK_THRESHOLD) {
      console.log(`[bulk] ${toQueue.length} <= ${IMMEDIATE_BULK_THRESHOLD} — duke perpunuar menjehere (si me pare)`);
      const results = [];
      await runWithConcurrency(toQueue, BULK_CONCURRENCY, async ({ product, lang }) => {
        const pid = normalizeProductId(product.id);
        try {
          const result = await localizeProduct(shop, token, pid, lang.targetLang, lang.locale, tone, glossary);
          results.push({ success: true, product_id: pid, locale: lang.locale, ...result });
        } catch (err) {
          results.push({ product_id: pid, product: product.title, locale: lang.locale, success: false, error: err.message });
        }
      });
      return res.json({ success: true, processed_immediately: true, results });
    }

    // I MADH — mbi prag, rrezik real timeout. Vendos ne rradhe (status
    // 'queued'), /poll (cron çdo 5 min) e procesion ne grupe permes
    // processQueuedTranslations() — asnje invokim i vetem s'rrezikon timeout.
    console.log(`[bulk] ${toQueue.length} > ${IMMEDIATE_BULK_THRESHOLD} — duke vendosur ne rradhe per /poll`);
    let queuedCount = 0;
    for (const { product, lang } of toQueue) {
      const pid = String(normalizeProductId(product.id));
      const { error: insertErr } = await supabase.from('translations').insert({
        shop, product_id: pid, locale: lang.locale, status: 'queued',
        original_title: product.title || '', original_description: '',
        product_handle: product.handle || '',
        translated_title: '', translated_description: ''
      });
      // 23505 = rreshti ekziston tashme (p.sh. nga nje bulk i meparshem qe
      // s'eshte perpunuar ende) — numerohet si i vendosur ne rradhe njesoj.
      if (!insertErr || insertErr.code === '23505') queuedCount++;
      else console.warn(`[bulk] Insert 'queued' deshtoi per ${pid}/${lang.locale}:`, insertErr.message);
    }

    res.json({
      success: true,
      processed_immediately: false,
      queued: queuedCount,
      message: `${queuedCount} translations queued for background processing (checked every ~5 minutes). Refresh this page to see progress.`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Deduplikimi i webhook-it: Shopify e dergon webhook-un 2-3 here per
// produkt (create + update i menjehershem + retry nese me vone se 5s).
// Pa kete Set, çdo thirrje e re = Sonnet i ri = cache WRITE = ~3.5 cent.
// Me kete: thirrja e dyte per të njejtin shop+product brenda 30s injorohet.
const recentWebhooks = new Set();

// Product create + update — lokalizon automatikisht
app.post('/webhook/product-create', requireWebhookHmac, async (req, res) => {
  res.status(200).send('OK');
  const rawBody = req.body;
  const shop = req.headers['x-shopify-shop-domain'];
  console.log('=== WEBHOOK product-create/update ===', shop);
  try {
    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
    if (!body.title || !body.id) return;

    // Deduplikim: Shop + product_id + 30 sekonda
    const webhookKey = `${shop}:${body.id}`;
    if (recentWebhooks.has(webhookKey)) {
      console.log(`[webhook-dedup] Anashkaluar thirrje e dyfishte per ${webhookKey}`);
      return;
    }
    recentWebhooks.add(webhookKey);
    setTimeout(() => recentWebhooks.delete(webhookKey), 30000);

    // Kontrollo nese produkti ekziston tashme - perdoret edhe per limit check
    const { data: existing } = await supabase
      .from('translations')
      .select('original_title, original_description')
      .eq('shop', shop)
      .eq('product_id', String(body.id))
      .limit(1);

    const isNewProduct = !existing || existing.length === 0;

    // Plan limit check - vetem per produkte te REJA. Produktet ekzistuese
    // mund te ri-perkthehen kur editohen (psh title/description ndryshon),
    // pavaresisht limitit - nuk shton ne numerimin e produkteve.
    if (isNewProduct) {
      const PLANS = app.locals.PLANS;
      if (PLANS) {
        const { data: storeData } = await supabase
          .from('stores').select('plan, plan_started_at').eq('shop', shop).single();
        const planName = storeData?.plan || 'free';
        const planStartedAt = storeData?.plan_started_at || null;
        const plan = PLANS[planName] || PLANS.free;
        const uniqueProducts = await getLocalizedProductCount(shop, planStartedAt);
        if (uniqueProducts >= plan.product_limit) {
          console.warn(`[plan-limit] Webhook blocked for ${shop} — ${planName} limit (${plan.product_limit}, used ${uniqueProducts})`);
          return;
        }
      }
    }

    if (isNewProduct) {
      // Produkt i ri — lokalizon direkt pa asnjë kontroll
      console.log(`New product detected: "${body.title}" — triggering localization`);
    } else {
      // Produkt ekzistues — lokalizon vetëm nëse titulli OSE description ka ndryshuar
      const currentDesc = (body.body_html || '').replace(/<[^>]*>/g, '').trim();
      const savedDesc = (existing[0]?.original_description || '').replace(/<[^>]*>/g, '').trim();
      const titleChanged = existing[0]?.original_title?.toLowerCase() !== body.title.toLowerCase();
      const descChanged = currentDesc.length > 0 && savedDesc !== currentDesc;

      if (!titleChanged && !descChanged) {
        console.log(`Product unchanged: "${body.title}" — skipping`);
        return;
      }

      console.log(`Product changed: "${body.title}" — title:${titleChanged} desc:${descChanged} — relocalizing`);
      await supabase.from('translations').delete()
        .eq('shop', shop)
        .eq('product_id', String(body.id));
    }

    console.log('Calling localizeProduct directly for:', body.title);
    setImmediate(async () => {
      try {
        const store = await getStore(shop);
        if (!store?.access_token) return;
        const glossary = store.glossary || 'checkout, Shopify';
        const savedLocales = store.selected_locales || [];
        const locales = savedLocales.length > 0
          ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
          : await getShopLocales(shop, store.access_token);
        if (!locales?.length) return;
        const pid = normalizeProductId(body.id);
        for (const lang of locales) {
          try {
            await localizeProduct(shop, store.access_token, pid, lang.targetLang, lang.locale, store.tone || 'professional', glossary);
            console.log(`[webhook] Done: ${body.title} → ${lang.locale}`);
          } catch(e) { console.error(`[webhook] Error ${lang.locale}:`, e.message); }
          await new Promise(r => setTimeout(r, 300));
        }
      } catch(e) { console.error('[webhook] Error:', e.message); }
    });
  } catch (err) {
    console.error('Webhook error:', err.message);
  }
});

// Product delete — fshi nga Supabase
app.post('/webhook/product-delete', async (req, res) => {
  res.status(200).send('OK');
  const rawBody = req.body;
  const shop = req.headers['x-shopify-shop-domain'];
  try {
    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
    if (!body.id) return;
    console.log('=== WEBHOOK product-delete ===', shop, body.id);
    await supabase.from('translations').delete()
      .eq('shop', shop)
      .eq('product_id', String(body.id));
    console.log('Deleted translations for product:', body.id);
  } catch (err) {
    console.error('Webhook delete error:', err.message);
  }
});

// Route bazë per compliance webhooks te regjistruara ne TOML si uri = "/webhook"
// Shopify dergon te gjitha compliance_topics te kjo URL me X-Shopify-Topic header
app.post('/webhook', requireWebhookHmac, (req, res) => {
  const topic = req.headers['x-shopify-topic'] || '';
  console.log(`[compliance] /webhook received topic: ${topic}`);
  if (topic === 'shop/redact') {
    res.status(200).send('OK');
    const body = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString()) : req.body;
    const shop = body?.myshopify_domain || req.headers['x-shopify-shop-domain'];
    if (shop) {
      supabase.from('translations').delete().eq('shop', shop).then(() =>
        supabase.from('stores').delete().eq('shop', shop)
      ).catch(e => console.error('[compliance] shop/redact error:', e.message));
    }
  } else {
    // customers/data_request, customers/redact — Getoify nuk ruan te dhena personale
    res.status(200).send('OK');
  }
});

// ─── COMPLIANCE WEBHOOKS (required for Shopify App Store) ────────────────────

// HMAC verification per te gjitha webhook-et e Shopify — kerkese e detyrueshme
// per aprovim ne Shopify App Store. Shopify dergon HMAC-SHA256 header
// 'x-shopify-hmac-sha256' me çdo webhook; nese nuk perputhet me SECRET-in
// tone, kerkesa refuzohet me 401 (dikush tjeter po perpiqet te dergoje data).
function verifyShopifyWebhookHmac(req) {
  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  if (!hmacHeader) return false;
  const secret = (process.env.SHOPIFY_API_SECRET || '').trim();
  if (!secret) return false;
  const rawBody = req.rawBody || (Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body)));
  const digest = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  const digestBuf = Buffer.from(digest);
  const hmacBuf = Buffer.from(hmacHeader);
  if (digestBuf.length !== hmacBuf.length) return false;
  return crypto.timingSafeEqual(digestBuf, hmacBuf);
}

// Middleware per compliance webhooks — bllokon kerkesa pa HMAC te vlefshme
function requireWebhookHmac(req, res, next) {
  if (!verifyShopifyWebhookHmac(req)) {
    console.warn('[hmac] Webhook HMAC verification failed — request rejected');
    return res.status(401).send('Unauthorized');
  }
  next();
}

// customers/data_request — merchant asks for customer data export
app.post('/webhook/customers/data-request', requireWebhookHmac, (req, res) => {
  // Getoify does not store personal customer data — nothing to export
  console.log('[compliance] customers/data_request received');
  res.status(200).send('OK');
});

// customers/redact — merchant asks to delete customer data
app.post('/webhook/customers/redact', requireWebhookHmac, (req, res) => {
  // Getoify does not store personal customer data — nothing to delete
  console.log('[compliance] customers/redact received');
  res.status(200).send('OK');
});

// shop/redact — shop uninstalled, delete all shop data
app.post('/webhook/shop/redact', requireWebhookHmac, async (req, res) => {
  res.status(200).send('OK');
  const rawBody = req.body;
  try {
    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
    const shop = body.myshopify_domain || req.headers['x-shopify-shop-domain'];
    if (!shop) return;
    console.log('[compliance] shop/redact — deleting all data for:', shop);
    await supabase.from('translations').delete().eq('shop', shop);
    await supabase.from('stores').delete().eq('shop', shop);
    console.log('[compliance] shop/redact done:', shop);
  } catch(e) {
    console.error('[compliance] shop/redact error:', e.message);
  }
});

app.post('/process-product', requireShopAuth, async (req, res) => {
  const shop = req.verifiedShop;
  const { productId, productTitle } = req.body;
  let pid;
  try {
    pid = normalizeProductId(productId);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  console.log('process-product called:', { shop, product_id: pid, productTitle });
  try {
    const store = await getStore(shop);
    console.log('store found:', store.shop, 'locales:', store.selected_locales, 'token:', store.access_token ? 'ok' : 'MISSING');
    const token = store.access_token;
    if (!token) throw new Error('No access_token in store');
    const tone = store.tone || 'professional and elegant';
    const glossary = store.glossary || 'checkout, Shopify';
    const savedLocales = store.selected_locales || [];

    // Hard plan limit check — COUNT(DISTINCT) via Supabase RPC
    const PLANS = app.locals.PLANS;
    if (PLANS) {
      const planName = store.plan || 'free';
      const planStartedAt2 = store.plan_started_at || null;
      const plan = PLANS[planName] || PLANS.free;
      const uniqueProducts = await getLocalizedProductCount(shop, planStartedAt2);
      console.warn(`[plan-limit] ${shop} ${planName}: ${uniqueProducts}/${plan.product_limit} products used`);
      if (uniqueProducts >= plan.product_limit) {
        console.warn(`[plan-limit] ${shop} hit ${planName} limit (${plan.product_limit}, used ${uniqueProducts})`);
      await sendNotification(
        `Limit reached: ${shop} (${planName})`,
        `<h2>Merchant hit plan limit</h2>
         <p><b>Store:</b> ${shop}</p>
         <p><b>Plan:</b> ${planName} (limit: ${plan.product_limit} products)</p>
         <p><b>Used:</b> ${uniqueProducts} products</p>
         <p><b>Time:</b> ${new Date().toISOString()}</p>
         <p>This merchant may be ready to upgrade.</p>`
      );
        return res.status(403).json({
          error: `Plan limit reached. Your ${plan.label} plan supports ${plan.product_limit} products.`,
          upgrade_url: `${process.env.APP_URL}/pricing`,
          plan: planName,
          limit: plan.product_limit
        });
      }
    }
    console.log('savedLocales:', savedLocales);
    const locales = savedLocales.length > 0
      ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
      : await getShopLocales(shop, token);
    console.log('locales to process:', locales);
    if (!locales || locales.length === 0) throw new Error('No locales found for this store');
    const results = [];
    for (const lang of locales) {
      try {
        await localizeProduct(shop, token, pid, lang.targetLang, lang.locale, tone, glossary);
        console.log(`Done: ${productTitle} (${pid}) in ${lang.targetLang}`);
        results.push({ product_id: pid, locale: lang.locale, success: true });
      } catch (err) {
        console.error(`Error ${lang.locale}:`, err.message);
        results.push({ product_id: pid, locale: lang.locale, success: false, error: err.message });
      }
      await new Promise(resolve => setTimeout(resolve, 300));
    }
    res.json({ success: true, product_id: pid, results });
  } catch (err) {
    console.error('Process error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Pastrues global, i pavarur, per rreshta 'processing' te ngecur — thirret
// PARA pollNewProducts(), jo brenda saj. Nuk prek logjiken ekzistuese te
// pollNewProducts() apo /bulk-localize-all fare — thjesht fshin rreshtat e
// vjeter 'processing' NE TE GJITHA shops, para se ato dy te lexojne
// databazen. Pasi rreshti eshte fshire, logjika e TYRE ekzistuese (needsLocalize,
// missingLocales) e sheh vetvetiu "s'ka rresht" dhe riprovon normalisht —
// pa pasur nevoje te ndryshohet asnje rresht i filtrimit te tyre.
async function cleanupStaleProcessingLocks() {
  const STALE_MS = 3 * 60 * 1000; // 3 min — njesoj si PROCESSING_LOCK_STALE_MS
  const cutoff = new Date(Date.now() - STALE_MS).toISOString();
  try {
    const { data: staleRows, error } = await supabase
      .from('translations')
      .delete()
      .eq('status', 'processing')
      .lt('created_at', cutoff)
      .select('shop, product_id, locale');
    if (error) { console.warn('[cleanup] Fshirja e locks te ngecur deshtoi:', error.message); return; }
    if (staleRows?.length > 0) {
      console.log(`[cleanup] Fshiu ${staleRows.length} rresht(a) 'processing' te ngecur (>3 min):`,
        staleRows.map(r => `${r.shop}/${r.product_id}/${r.locale}`).join(', '));
    }
  } catch(e) {
    console.warn('[cleanup] Gabim:', e.message);
  }
}

async function pollNewProducts() {
  console.log('Polling for new products...');
  try {
    const { data: stores } = await supabase.from('stores').select('*');
    if (!stores || !stores.length) return;

    for (const store of stores) {
      const token = store.access_token;
      const shop = store.shop;
      const tone = store.tone || 'professional and elegant';
      const glossary = store.glossary || 'checkout, Shopify';

      // Skip stores with old/invalid tokens
      if (!token || token.startsWith('shpua_')) {
        console.log('Skipping store with invalid token:', shop);
        continue;
      }

      // Plan limit check — skip polling for stores that hit their product limit
      const PLANS = app.locals.PLANS;
      let uniqueProducts = 0;
      let planLimit = 15;
      if (PLANS) {
        const planName = store.plan || 'free';
        const planStartedAt = store.plan_started_at || null;
        const plan = PLANS[planName] || PLANS.free;
        planLimit = plan.product_limit;
        uniqueProducts = await getLocalizedProductCount(shop, planStartedAt);
        console.warn(`[poll] ${shop} ${planName}: ${uniqueProducts}/${planLimit} products used`);
        if (uniqueProducts >= planLimit) {
          console.warn(`[poll] Skipping ${shop} — ${planName} limit reached (${planLimit}, used ${uniqueProducts})`);
          continue;
        }
      }

      try {
        const res = await axios.get(
          `https://${shop}/admin/api/2026-07/products.json?limit=50&order=created_at+desc`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );

        for (const product of res.data.products) {
          // Only localize if this product_id has never been translated.
          // Never delete existing translations automatically — this caused
          // data corruption where old product descriptions overwrote new ones.
          const { data } = await supabase
            .from('translations')
            .select('id')
            .eq('shop', shop)
            .eq('product_id', String(product.id))
            .limit(1);

          const needsLocalize = !data || data.length === 0;

          if (needsLocalize) {

            // Re-check limit on each new product — stop mid-run if reached
            if (PLANS && uniqueProducts >= planLimit) {
              console.log(`[poll] ${shop} reached limit (${planLimit}) mid-run — stopping`);
              break;
            }

            console.log('New product found via polling:', product.title);
            const savedLocales = store.selected_locales || [];
            const locales = savedLocales.length > 0
              ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
              : await getShopLocales(shop, token);
            for (const lang of locales) {
              try {
                await localizeProduct(shop, token, normalizeProductId(product.id), lang.targetLang, lang.locale, tone, glossary);
                console.log(`Poll done: ${product.title} in ${lang.targetLang}`);
              } catch(e) {
                console.error('Poll localize error:', e.message);
              }
            }
            if (PLANS) uniqueProducts++;
          }
        }
      } catch(e) {
        console.error('Poll store error:', shop, e.message);
      }
    }
  } catch(e) {
    console.error('Poll error:', e.message);
  }
}

// Collection webhook
app.post('/webhook/collection-create', async (req, res) => {
  res.status(200).send('OK');
  const rawBody = req.body;
  const shop = req.headers['x-shopify-shop-domain'];
  console.log('=== WEBHOOK collection-create/update ===', shop);
  try {
    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
    if (!body.id) return;
    const store = await getStore(shop).catch(() => null);
    if (!store?.access_token) return;
    const savedLocales = store.selected_locales || [];
    if (!savedLocales.length) return;
    const glossary = store.glossary || 'checkout, Shopify';
    for (const locale of savedLocales) {
      try {
        await localizeCollection(shop, store.access_token, body.id, LOCALE_MAP[locale] || locale, locale, glossary);
        console.log(`[collection webhook] Done: ${body.title || body.id} → ${locale}`);
      } catch(e) { console.error('[collection webhook] Error:', locale, e.message); }
      await new Promise(r => setTimeout(r, 300));
    }
  } catch(err) { console.error('[collection webhook] Error:', err.message); }
});

// Procesón nje grup te KUFIZUAR (QUEUE_BATCH_SIZE) çiftesh (produkt, gjuhe)
// te shenuara 'queued' nga /bulk-localize-all. Thirret nga /poll (cron çdo
// 5 min) — jo brenda vete kerkeses HTTP te /bulk-localize-all — pikerisht
// per te shmangur rrezikun e timeout-it per plane te medha (Enterprise).
// Rradha e mbetur (nese ka me shume se QUEUE_BATCH_SIZE) vazhdon ne
// invokimin tjeter te cron-it, automatikisht, pa nevoje per veprim shtese.
async function processQueuedTranslations() {
  try {
    const { data: queuedRows, error } = await supabase
      .from('translations')
      .select('shop, product_id, locale')
      .eq('status', 'queued')
      .order('created_at', { ascending: true })
      .limit(QUEUE_BATCH_SIZE);
    if (error) { console.warn('[queue] Fetch i rradhes deshtoi:', error.message); return; }
    if (!queuedRows?.length) return;

    console.log(`[queue] Duke perpunuar ${queuedRows.length} çifte nga rradha`);

    // Cache i vogel per store — disa rreshta mund t'i perkasin te njejtit
    // shop, s'ka nevoje te therrasim getStore() per secilin veç e veç.
    const storeCache = new Map();
    async function getStoreCached(shop) {
      if (!storeCache.has(shop)) storeCache.set(shop, await getStore(shop).catch(() => null));
      return storeCache.get(shop);
    }

    await runWithConcurrency(queuedRows, BULK_CONCURRENCY, async (row) => {
      // KRITIKE: fshi rreshtin 'queued' PARA se te therrasim localizeProduct.
      // localizeProduct e ndertoi vete lock-un e vet me INSERT (status
      // 'processing') mbi te njejtin constraint unik (shop, product_id,
      // locale) qe perdor edhe rreshti 'queued' — nese s'e fshijme kete
      // rresht paraprakisht, INSERT-i i localizeProduct do te perplasej me
      // te (23505) dhe do ta trajtonte gabimisht si "dikush tjeter po e
      // procesion", duke e anashkaluar pa e perkthyer fare.
      await supabase.from('translations').delete()
        .eq('shop', row.shop).eq('product_id', row.product_id).eq('locale', row.locale).eq('status', 'queued');

      const store = await getStoreCached(row.shop);
      if (!store?.access_token) {
        console.warn(`[queue] ${row.shop} pa access_token te vlefshem, anashkalohet ${row.product_id}/${row.locale}`);
        return;
      }
      const targetLang = LOCALE_MAP[row.locale] || row.locale;
      try {
        await localizeProduct(row.shop, store.access_token, row.product_id, targetLang, row.locale, store.tone || 'professional', store.glossary || 'checkout, Shopify');
        console.log(`[queue] Done: ${row.shop} ${row.product_id}/${row.locale}`);
      } catch(e) {
        console.error(`[queue] Error ${row.shop} ${row.product_id}/${row.locale}:`, e.message);
      }
      await new Promise(r => setTimeout(r, 200));
    });
  } catch(e) {
    console.error('[queue] Gabim i pergjithshem:', e.message);
  }
}

// Vercel Cron endpoint — called every 5 minutes by vercel.json crons config
// setInterval does not work on Vercel serverless — use this instead
app.get('/poll', async (req, res) => {
  await cleanupStaleProcessingLocks();
  await pollNewProducts();
  await processQueuedTranslations();
  res.json({ ok: true, time: new Date().toISOString() });
});

// Keep setInterval only for local development
if (process.env.NODE_ENV !== 'production') {
  setInterval(pollNewProducts, 5 * 60 * 1000);
  setTimeout(pollNewProducts, 15000);
}

async function autoResetWebhooks() {
  try {
    const { data: stores } = await supabase.from('stores').select('shop, access_token');
    if (!stores?.length) return;
    const webhookTopics = [
      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` },
      { topic: 'collections/create', address: `${APP_URL}/webhook/collection-create` },
      { topic: 'collections/update', address: `${APP_URL}/webhook/collection-create` }
    ];
    for (const store of stores) {
      if (!store.access_token || store.access_token.startsWith('shpua_')) continue;
      try {
        const listRes = await axios.get(`https://${store.shop}/admin/api/2026-07/webhooks.json`,
          { headers: { 'X-Shopify-Access-Token': store.access_token }, timeout: 10000 });
        const existing = listRes.data.webhooks || [];
        const allCorrect = webhookTopics.every(wh => existing.some(e => e.topic === wh.topic && e.address === wh.address));
        if (allCorrect) { console.log(`[auto-webhooks] OK: ${store.shop}`); continue; }
        for (const wh of existing) {
          await axios.delete(`https://${store.shop}/admin/api/2026-07/webhooks/${wh.id}.json`,
            { headers: { 'X-Shopify-Access-Token': store.access_token }, timeout: 10000 });
        }
        for (const wh of webhookTopics) {
          await axios.post(`https://${store.shop}/admin/api/2026-07/webhooks.json`,
            { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
            { headers: { 'X-Shopify-Access-Token': store.access_token, 'Content-Type': 'application/json' }, timeout: 10000 });
        }
        console.log(`[auto-webhooks] Reset OK: ${store.shop}`);
      } catch(e) { console.warn(`[auto-webhooks] Failed for ${store.shop}:`, e.message); }
    }
  } catch(e) { console.error('[auto-webhooks] Error:', e.message); }
}

// TEST ENDPOINT — remove after testing
app.post('/test-prompt', async (req, res) => {
  const { title, lang, shop } = req.body;

  // Kontroll limiti edhe per test-prompt — kjo ishte rruga e vetme e mbetur
  // e pabllokuar. Pa shop, nuk mund te kontrollojme; nese shop eshte dhene,
  // bllokohet si cdo rruge tjeter.
  if (shop && app.locals.PLANS) {
    try {
      const store = await getStore(shop);
      if (store) {
        const planName = store.plan || 'free';
        const plan = app.locals.PLANS[planName] || app.locals.PLANS.free;
        const planStartedAt = store.plan_started_at || null;
        let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(10000);
        if (planStartedAt) q = q.gte('created_at', planStartedAt);
        const { data: rows } = await q;
        const uniqueCount = new Set((rows || []).map(r => String(r.product_id))).size;
        if (uniqueCount >= plan.product_limit) {
          return res.status(403).json({
            error: `Plan limit reached (${uniqueCount}/${plan.product_limit}). Upgrade to continue.`,
            limit: plan.product_limit,
            used: uniqueCount
          });
        }
      }
    } catch(limitErr) {
      if (limitErr.message?.startsWith('PLAN_LIMIT')) {
        return res.status(403).json({ error: limitErr.message });
      }
      console.warn('[test-prompt] limit check failed:', limitErr.message);
    }
  }

  const product = { title, product_type: '', tags: '', body_html: '' };
  try {
    const result = await generateProductCopy(product, lang, 'checkout, Shopify', '', null, [], shop);
    res.json(result);
  } catch(e) {
    if (e.message?.startsWith('PLAN_LIMIT')) {
      return res.status(403).json({ error: e.message });
    }
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`Getoify server running on port ${PORT}`);
  setTimeout(autoResetWebhooks, 5000);
});