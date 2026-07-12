1	const express = require('express');
     2	const crypto = require('crypto');
     3	const dotenv = require('dotenv');
     4	const axios = require('axios');
     5	const path = require('path');
     6	const { createClient } = require('@supabase/supabase-js');
     7	
     8	dotenv.config({ override: false });
     9	
    10	const app = express();
    11	
    12	// Ruaj raw bytes te req.rawBody para parsing — i vetmi menyrim i besueshëm
    13	// per HMAC verification te Shopify webhooks. express.raw() dhe express.json()
    14	// ne paralel shkaktojne konflikt: nje prej tyre merr streamin, tjetri merr
    15	// objekt JSON. JSON.stringify(object) nuk prodhon bytes identike me payload-in
    16	// origjinal (whitespace, key order) → HMAC deshton gjithmone.
    17	app.use(express.json({
    18	  verify: (req, res, buf) => { req.rawBody = buf; }
    19	}));
    20	app.use(express.static(path.join(__dirname, 'public')));
    21	
    22	const { 
    23	  SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_SCOPES, 
    24	  APP_URL, SUPABASE_URL, SUPABASE_SERVICE_KEY
    25	} = process.env;
    26	
    27	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
    28	
    29	// ─── SHOP SESSION AUTH ────────────────────────────────────────────────────
    30	// Zëvendëson "shop=X ne URL" si identitet. Pas OAuth-it te suksesshem
    31	// (/auth/callback), lëshohet nje cookie e nënshkruar (HttpOnly, e
    32	// pafalsifikueshme pa SHOPIFY_API_SECRET) qe deshmon se ky browser ka
    33	// kaluar vertet OAuth-in per ate shop. Route-t e ndjeshme (te dhena/veprime
    34	// per nje shop specifik) kerkojne kete cookie permes requireShopAuth, dhe
    35	// perdorin req.verifiedShop — jo me req.query.shop apo req.body.shop, qe
    36	// deri tani ishin te falsifikueshme nga kushdo qe di emrin e shop-it.
    37	const SESSION_COOKIE_NAME = 'getoify_session';
    38	const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 dite
    39	
    40	function toBase64Url(buf) {
    41	  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    42	}
    43	function fromBase64Url(str) {
    44	  str = str.replace(/-/g, '+').replace(/_/g, '/');
    45	  while (str.length % 4) str += '=';
    46	  return Buffer.from(str, 'base64');
    47	}
    48	
    49	function signSession(shop) {
    50	  const payload = toBase64Url(Buffer.from(JSON.stringify({ shop, iat: Date.now() })));
    51	  const sig = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(payload).digest('hex');
    52	  return `${payload}.${sig}`;
    53	}
    54	
    55	function verifySession(cookieValue) {
    56	  if (!cookieValue) return null;
    57	  const dotIdx = cookieValue.lastIndexOf('.');
    58	  if (dotIdx === -1) return null;
    59	  const payload = cookieValue.slice(0, dotIdx);
    60	  const sig = cookieValue.slice(dotIdx + 1);
    61	  const expectedSig = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(payload).digest('hex');
    62	  const sigBuf = Buffer.from(sig, 'utf8');
    63	  const expectedBuf = Buffer.from(expectedSig, 'utf8');
    64	  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
    65	  try {
    66	    const data = JSON.parse(fromBase64Url(payload).toString('utf8'));
    67	    if (!data.shop || !data.iat) return null;
    68	    if (Date.now() - data.iat > SESSION_MAX_AGE_MS) return null;
    69	    return data.shop;
    70	  } catch (e) {
    71	    return null;
    72	  }
    73	}
    74	
    75	function getCookie(req, name) {
    76	  const header = req.headers.cookie;
    77	  if (!header) return null;
    78	  for (const part of header.split(';')) {
    79	    const idx = part.indexOf('=');
    80	    if (idx === -1) continue;
    81	    if (part.slice(0, idx).trim() === name) return decodeURIComponent(part.slice(idx + 1).trim());
    82	  }
    83	  return null;
    84	}
    85	
    86	// Kerkohet ne cdo route qe lexon/shkruan te dhena te nje shop specifik.
    87	// Verifikon cookie-n e sesionit dhe vendos req.verifiedShop — handler-at
    88	// duhet ta perdorin kete, jo me req.query.shop apo req.body.shop.
    89	function requireShopAuth(req, res, next) {
    90	  const shop = verifySession(getCookie(req, SESSION_COOKIE_NAME));
    91	  if (!shop) return res.status(401).json({ error: 'Not authenticated. Please reconnect your store.' });
    92	  req.verifiedShop = shop;
    93	  next();
    94	}
    95	
    96	// Per endpoint-et e mirembajtjes (jo per merchant, per ty si zhvillues) —
    97	// kerkon ADMIN_API_KEY (query ?admin_key= ose header x-admin-key) ne vend
    98	// te session cookie-t, sepse keto s'kalojne nga dashboard-i i merchant-it.
    99	// Nese ADMIN_API_KEY s'eshte vendosur ne env, route-t bllokohen (fail-closed).
   100	function requireAdminKey(req, res, next) {
   101	  const expected = process.env.ADMIN_API_KEY;
   102	  if (!expected) {
   103	    console.warn('[admin-key] ADMIN_API_KEY nuk eshte vendosur — route i mirembajtjes bllokohet per siguri');
   104	    return res.status(503).json({ error: 'Admin routes are not configured' });
   105	  }
   106	  const provided = String(req.query.admin_key || req.headers['x-admin-key'] || '');
   107	  const providedBuf = Buffer.from(provided);
   108	  const expectedBuf = Buffer.from(expected);
   109	  if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
   110	    return res.status(401).json({ error: 'Unauthorized' });
   111	  }
   112	  next();
   113	}
   114	
   115	// ─── OAUTH CALLBACK HARDENING ─────────────────────────────────────────────
   116	// Format i vlefshem per domain shop-i, sipas rregullit qe vete Shopify e
   117	// dokumenton: vetem shkronja a-z, numra 0-9, pika dhe viza, dhe DUHET te
   118	// mbaroje me ".myshopify.com". Perdoret PARA se `shop` te futet ne çdo URL
   119	// te jashtme (/auth, /auth/callback) — mbyll rrugen e SSRF-it ku dikush do
   120	// te vendoste nje host arbitrar (p.sh. "shop=intern.local") dhe do e bente
   121	// serverin tone te dergonte kerkesa (bashke me client_secret-in tone!) atje.
   122	function isValidShopDomain(shop) {
   123	  return typeof shop === 'string' && /^[a-zA-Z0-9.-]+\.myshopify\.com$/.test(shop);
   124	}
   125	
   126	// Verifikon hmac-un qe Shopify e shton te query string i /auth/callback —
   127	// KY eshte ndryshe nga HMAC i webhook-ve (verifyShopifyWebhookHmac me poshte):
   128	// per OAuth callback, Shopify e nenshkruan STRING-un e parametrave (jo trupin
   129	// e kerkeses), dhe rezultati eshte HEX (jo base64). Sipas shopify.dev:
   130	// hiq 'hmac' (dhe 'signature' nese ekziston), rradhit çelesat e mbetur
   131	// leksikografikisht, bashko si "kyc=vlere" me '&', HMAC-SHA256 me client
   132	// secret, krahaso hex digest-in me parametrin hmac.
   133	function verifyOAuthCallbackHmac(query) {
   134	  const { hmac, signature, ...rest } = query;
   135	  if (!hmac || typeof hmac !== 'string') return false;
   136	  const message = Object.keys(rest).sort().map(key => `${key}=${rest[key]}`).join('&');
   137	  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(message).digest('hex');
   138	  const digestBuf = Buffer.from(digest, 'utf8');
   139	  const hmacBuf = Buffer.from(hmac, 'utf8');
   140	  if (digestBuf.length !== hmacBuf.length) return false;
   141	  return crypto.timingSafeEqual(digestBuf, hmacBuf);
   142	}
   143	
   144	// Intercept Shopify 401 — mark token invalid in Supabase
   145	axios.interceptors.response.use(
   146	  res => res,
   147	  async err => {
   148	    const url = err.config?.url || '';
   149	    const status = err.response?.status;
   150	
   151	    // 429 nga Shopify — i mundshem tani me konkurrence ne bulk-localize-all
   152	    // (disa produkte njekohesisht = me shume kerkesa/sekonde te i njejti shop).
   153	    // Rites NJE here me Retry-After (ose 2s fallback), max 3 perpjekje gjithsej.
   154	    if (status === 429 && url.includes('myshopify.com')) {
   155	      const cfg = err.config;
   156	      cfg.__retryCount = (cfg.__retryCount || 0) + 1;
   157	      if (cfg.__retryCount <= 3) {
   158	        const retryAfter = parseFloat(err.response.headers?.['retry-after']) || 2;
   159	        console.warn(`[429] Shopify rate limit — riprovo ${url} pas ${retryAfter}s (perpjekja ${cfg.__retryCount}/3)`);
   160	        await new Promise(r => setTimeout(r, retryAfter * 1000));
   161	        return axios(cfg);
   162	      }
   163	      console.error(`[429] Shopify rate limit — u dorezuar pas 3 perpjekjeve: ${url}`);
   164	    }
   165	
   166	    if (status === 401 && url.includes('myshopify.com')) {
   167	      const shopMatch = url.match(/https:\/\/([^/]+)/);
   168	      if (shopMatch) {
   169	        const shop = shopMatch[1];
   170	        console.warn(`[401] Token invalid for ${shop} — marking in Supabase`);
   171	        await supabase.from('stores').update({ token_invalid: true }).eq('shop', shop);
   172	      }
   173	    }
   174	    if (status !== 401 && url.includes('myshopify.com/admin/oauth/access_token')) {
   175	      const shopMatch = url.match(/https:\/\/([^/]+)/);
   176	      if (shopMatch) {
   177	        await supabase.from('stores').update({ token_invalid: false }).eq('shop', shopMatch[1]);
   178	      }
   179	    }
   180	    return Promise.reject(err);
   181	  }
   182	);
   183	
   184	const { normalizeProductId } = require('./lib/product-id');
   185	const { fetchAllRows } = require('./lib/supabase-pagination');
   186	const { localizeCollection, bulkLocalizeCollections } = require('./lib/localize-collection');
   187	const { localizeArticle, bulkLocalizeBlogs } = require('./lib/localize-blog');
   188	// Stripe dhe lib/shopify-billing.js u hoqen — kishin /checkout dhe /billing/callback
   189	// te vet qe konfliktonin (Express perdor handler-in e PARE te regjistruar per
   190	// te njejtin path) me /checkout dhe /billing/callback e ndertuara me poshte ne
   191	// kete file. Stripe ishte registruar I PARI dhe interceptonte CDO kerkese
   192	// /checkout, duke ridrejtuar merchant te checkout.stripe.com — kjo eshte
   193	// shkaku i sakte i refuzimit nga Shopify (1.2.1 off-platform billing).
   194	// Tani /checkout dhe /billing/callback me poshte jane TE VETMET handlers.
   195	
   196	// ─── WIDGET SCRIPTTAG ─────────────────────────────────────────────────────
   197	
   198	async function installScriptTag(shop, token) {
   199	  const scriptUrl = `${APP_URL}/widget.js`;
   200	  try {
   201	    const existing = await axios.get(
   202	      `https://${shop}/admin/api/2024-01/script_tags.json`,
   203	      { headers: { 'X-Shopify-Access-Token': token } }
   204	    );
   205	    const alreadyInstalled = (existing.data.script_tags || []).some(s => s.src === scriptUrl);
   206	    if (alreadyInstalled) { console.log(`[widget] ScriptTag already installed: ${shop}`); return; }
   207	    await axios.post(
   208	      `https://${shop}/admin/api/2024-01/script_tags.json`,
   209	      { script_tag: { event: 'onload', src: scriptUrl } },
   210	      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
   211	    );
   212	    console.log(`[widget] ScriptTag installed: ${shop}`);
   213	  } catch(e) {
   214	    console.error(`[widget] Install failed: ${shop}`, e.response?.data || e.message);
   215	  }
   216	}
   217	
   218	async function removeScriptTag(shop, token) {
   219	  const scriptUrl = `${APP_URL}/widget.js`;
   220	  try {
   221	    const existing = await axios.get(
   222	      `https://${shop}/admin/api/2024-01/script_tags.json`,
   223	      { headers: { 'X-Shopify-Access-Token': token } }
   224	    );
   225	    for (const tag of (existing.data.script_tags || [])) {
   226	      if (tag.src === scriptUrl) {
   227	        await axios.delete(
   228	          `https://${shop}/admin/api/2024-01/script_tags/${tag.id}.json`,
   229	          { headers: { 'X-Shopify-Access-Token': token } }
   230	        );
   231	        console.log(`[widget] ScriptTag removed: ${shop}`);
   232	      }
   233	    }
   234	  } catch(e) {
   235	    console.error(`[widget] Remove failed: ${shop}`, e.response?.data || e.message);
   236	  }
   237	}
   238	
   239	// Install widget manually — thirre nje here per stores ekzistuese
   240	// https://getoify.com/install-widget-manual?shop=xxx
   241	app.get('/install-widget-manual', requireAdminKey, async (req, res) => {
   242	  const { shop } = req.query;
   243	  if (!shop) return res.status(400).json({ error: 'Missing shop' });
   244	  try {
   245	    const { data: store } = await supabase
   246	      .from('stores')
   247	      .select('access_token')
   248	      .eq('shop', shop)
   249	      .single();
   250	    if (!store?.access_token) return res.status(404).json({ error: 'Store not found' });
   251	    await installScriptTag(shop, store.access_token);
   252	    res.json({ success: true, shop, message: 'Widget installed' });
   253	  } catch(e) {
   254	    res.status(500).json({ error: e.message });
   255	  }
   256	});
   257	
   258	// Widget config endpoint — widget.js e thirr kete per te marre gjuhet aktive
   259	app.get('/widget-config', async (req, res) => {
   260	  const { shop } = req.query;
   261	  if (!shop) return res.status(400).json({ error: 'Missing shop' });
   262	  res.header('Access-Control-Allow-Origin', '*');
   263	  try {
   264	    const { data } = await supabase
   265	      .from('stores')
   266	      .select('selected_locales')
   267	      .eq('shop', shop)
   268	      .single();
   269	    const locales = data?.selected_locales || [];
   270	    res.json({ shop, locales });
   271	  } catch(e) {
   272	    res.json({ shop, locales: [] });
   273	  }
   274	});
   275	
   276	const SHOPIFY_PRODUCTS_PAGE = 250;
   277	const SHOPIFY_PRODUCTS_TIMEOUT_MS = 60000;
   278	
   279	// Planete e Getoify — product_limit eshte numri max i produkteve unike
   280	// qe mund te lokalizohen gjate periudhes se planit. Perdoret nga te gjitha
   281	// endpoint-et per te bllokuar tejkalimin e limitit. DUHET te jete ketu
   282	// (globale) sepse app.locals.PLANS lexohet nga disa endpoint — ne te kaluaren
   283	// kurrë nuk u caktua, prandaj if (PLANS) ishte gjithmone false dhe limitet
   284	// nuk funksiononin fare.
   285	// Gjuhet e suportuara nga Getoify — merchant zgjedh nga keto
   286	const SUPPORTED_LOCALES = {
   287	  // Europë Perëndimore (tregjet kryesore)
   288	  'en': 'English',
   289	  'fr': 'French',
   290	  'de': 'German',
   291	  'it': 'Italian',
   292	  'es': 'Spanish',
   293	  'nl': 'Dutch',
   294	  'pt-BR': 'Portuguese (Brazil)',
   295	  'pt-PT': 'Portuguese (Portugal)',
   296	  'pl': 'Polish',
   297	  // Skandinavia (ecommerce i fortë)
   298	  'sv': 'Swedish',
   299	  'da': 'Danish',
   300	  'nb': 'Norwegian',
   301	  // Europë Lindore (në rritje)
   302	  'cs': 'Czech',
   303	  'ro': 'Romanian',
   304	  'hu': 'Hungarian',
   305	  // Tregje të mëdha globale
   306	  'ar': 'Arabic',
   307	  'ja': 'Japanese',
   308	  'ko': 'Korean',
   309	  'tr': 'Turkish',
   310	  'id': 'Indonesian',
   311	};
   312	
   313	const PLANS = {
   314	  free:        { label: 'Free',       product_limit: 15,   bulk_limit: 15,   language_limit: 1  },
   315	  description: { label: 'Local',      product_limit: 50,   bulk_limit: 50,   language_limit: 1  },
   316	  starter:     { label: 'Starter',    product_limit: 125,  bulk_limit: 125,  language_limit: 2  },
   317	  growth:      { label: 'Growth',     product_limit: 300,  bulk_limit: 300,  language_limit: 5  },
   318	  pro:         { label: 'Pro',        product_limit: 700,  bulk_limit: 700,  language_limit: 10 },
   319	  enterprise:  { label: 'Enterprise', product_limit: 1400, bulk_limit: 1400, language_limit: 20 },
   320	};
   321	app.locals.PLANS = PLANS;
   322	app.locals.SUPPORTED_LOCALES = SUPPORTED_LOCALES;
   323	
   324	// Funksioni ndihmës per COUNT(DISTINCT product_id) — perdor Supabase RPC
   325	// per te shmangur problemin e limitit te rreshtave (default 1000, max 10000).
   326	// Me SQL DISTINCT, kjo eshte me e sakt dhe me performante se deduplication
   327	// ne JavaScript pas fetch-imit te mijera rreshtave.
   328	async function getLocalizedProductCount(shop, planStartedAt) {
   329	  try {
   330	    const { data, error } = await supabase.rpc('get_localized_product_count', {
   331	      p_shop: shop,
   332	      p_started_at: planStartedAt || null
   333	    });
   334	    if (error) throw error;
   335	    return typeof data === 'number' ? data : parseInt(data || '0', 10);
   336	  } catch(e) {
   337	    console.warn('[plan-count] RPC failed, fallback to query:', e.message);
   338	    // Fallback: query me limit te larte
   339	    let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(50000);
   340	    if (planStartedAt) q = q.gte('created_at', planStartedAt);
   341	    const { data: rows } = await q;
   342	    return new Set((rows || []).map(r => String(r.product_id))).size;
   343	  }
   344	}
   345	
   346	
   347	// Sa PRODUKTE perpunohen njekohesisht ne bulk-localize-all. Lokalet brenda
   348	// nje produkti TE VETEM mbeten sekuenciale (shih processProductLocales) —
   349	// arkitektura "Sonnet nje here, Gemini per pjesen tjeter" varet nga kjo
   350	// rradhitje, prandaj konkurrenca aplikohet vetem mes produkteve te ndryshme.
   351	const BULK_CONCURRENCY = 4;
   352	
   353	// Ekzekuton 'items' me konkurrence maksimale 'limit', pa varesi te jashtme.
   354	// 'limit' "runner" lupa rrjedhin paralel, secila merr artikullin tjeter te
   355	// lire sapo perfundon te vetin — nuk pret "batch"-in te plotesohet (me
   356	// efikase se chunking i thjeshte ne grupe fikse).
   357	async function runWithConcurrency(items, limit, worker) {
   358	  let nextIndex = 0;
   359	  async function runNext() {
   360	    while (nextIndex < items.length) {
   361	      const i = nextIndex++;
   362	      await worker(items[i], i);
   363	    }
   364	  }
   365	  const runners = Array.from({ length: Math.min(limit, items.length) }, () => runNext());
   366	  await Promise.all(runners);
   367	}
   368	
   369	const LOCALE_MAP = {
   370	  'en': 'English', 'fr': 'French', 'de': 'German', 'it': 'Italian',
   371	  'es': 'Spanish', 'nl': 'Dutch', 'pt-PT': 'Portuguese', 'pt-BR': 'Brazilian Portuguese',
   372	  'pt': 'Portuguese', 'pl': 'Polish', 'sv': 'Swedish', 'da': 'Danish',
   373	  'nb': 'Norwegian', 'cs': 'Czech', 'ro': 'Romanian', 'hu': 'Hungarian',
   374	  'ar': 'Arabic', 'ja': 'Japanese', 'ko': 'Korean', 'tr': 'Turkish',
   375	  'id': 'Indonesian', 'fi': 'Finnish', 'zh': 'Chinese', 'hi': 'Hindi'
   376	};
   377	
   378	// Static pages
   379	app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
   380	app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
   381	app.get('/tone', (req, res) => res.sendFile(path.join(__dirname, 'public', 'tone.html')));
   382	app.get('/glossary', (req, res) => res.sendFile(path.join(__dirname, 'public', 'glossary.html')));
   383	app.get('/products-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'products.html')));
   384	app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'public', 'settings.html')));
   385	app.get('/autosync', (req, res) => res.sendFile(path.join(__dirname, 'public', 'autosync.html')));
   386	app.get('/product', (req, res) => res.sendFile(path.join(__dirname, 'public', 'product-detail.html')));
   387	app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
   388	app.get('/language-switcher', (req, res) => res.sendFile(path.join(__dirname, 'public', 'language-switcher.html')));
   389	app.get('/google6e865cb2268111cc.html', (req, res) => res.send('google-site-verification: google6e865cb2268111cc.html'));
   390	app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
   391	app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
   392	
   393	// ─── SHOPIFY BILLING API ─────────────────────────────────────────────────────
   394	const PLAN_PRICES = {
   395	  free:        { monthly: 0,   yearly: 0,   label: 'Free'       },
   396	  description: { monthly: 9,   yearly: 8,   label: 'Local'      },
   397	  starter:     { monthly: 19,  yearly: 15,  label: 'Starter'    },
   398	  growth:      { monthly: 49,  yearly: 39,  label: 'Growth'     },
   399	  pro:         { monthly: 99,  yearly: 79,  label: 'Pro'        },
   400	  enterprise:  { monthly: 199, yearly: 159, label: 'Enterprise' },
   401	};
   402	
   403	// Funksion ndihmës per dergimin e email notifikimeve me Resend
   404	// Thirret kur merchant paguan plan te ri ose arrin limitin
   405	async function sendNotification(subject, html) {
   406	  const apiKey = process.env.RESEND_API_KEY;
   407	  const to = process.env.NOTIFY_EMAIL || 'contact@premiumartisan.fr';
   408	  if (!apiKey) return; // Nese RESEND_API_KEY nuk eshte vendosur, kaperceje
   409	  try {
   410	    await axios.post('https://api.resend.com/emails', {
   411	      from: 'Getoify <notifications@getoify.com>',
   412	      to,
   413	      subject,
   414	      html
   415	    }, { headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' } });
   416	    console.log(`[notify] Email sent: ${subject}`);
   417	  } catch(e) {
   418	    console.warn('[notify] Email failed:', e.response?.data || e.message);
   419	  }
   420	}
   421	
   422	// /plan — perdoret nga settings.html (loadPlan) per te shfaqur planin aktual.
   423	// Zevendeson /plan e vjeter te lib/stripe.js — tani lexon direkt nga stores
   424	// (plan, billing_cycle) qe perditesohen nga /billing/callback me poshte.
   425	app.get('/plan', requireShopAuth, async (req, res) => {
   426	  const shop = req.verifiedShop;
   427	  try {
   428	    const { data: store } = await supabase
   429	      .from('stores')
   430	      .select('plan, billing_cycle, billing_id')
   431	      .eq('shop', shop)
   432	      .single();
   433	    res.json({
   434	      plan: store?.plan || 'free',
   435	      billing_cycle: store?.billing_cycle || null,
   436	      has_subscription: !!store?.billing_id
   437	    });
   438	  } catch(e) {
   439	    res.json({ plan: 'free', billing_cycle: null, has_subscription: false });
   440	  }
   441	});
   442	
   443	// Zbulon nese dyqani eshte development/test store i Shopify Partners —
   444	// keto NUK mund te krijojne RecurringApplicationCharge me test:false, Shopify
   445	// e refuzon. Shopify reviewer-at GJITHMONE testojne ne dev stores — kjo eshte
   446	// shkaku i sakte i "billing failed when attempting to subscribe" te raportuar.
   447	// Default i sigurt kur s'mund te percaktohet: test:true (ne kete faze pa
   448	// klient pagues real, kjo eshte gjithmone zgjedhja e duhur — false negative
   449	// (test:true ne dyqan real) thjesht s'mbledh para njehere, false positive
   450	// (test:false ne dev store) e bllokon plotesisht flow-in e billing-ut).
   451	async function isDevelopmentStore(shop, token) {
   452	  try {
   453	    const shopRes = await axios.get(
   454	      `https://${shop}/admin/api/2024-01/shop.json`,
   455	      { headers: { 'X-Shopify-Access-Token': token } }
   456	    );
   457	    const planName = (shopRes.data.shop?.plan_name || '').toLowerCase();
   458	    const planDisplay = (shopRes.data.shop?.plan_display_name || '').toLowerCase();
   459	    return planName.includes('partner_test') || planName.includes('dev') ||
   460	      planName === 'staff_business' || planDisplay.includes('development') ||
   461	      planDisplay.includes('partner');
   462	  } catch(e) {
   463	    console.warn('[billing] Could not determine store plan type, defaulting to test:true for safety:', e.message);
   464	    return true;
   465	  }
   466	}
   467	
   468	app.get('/checkout', async (req, res) => {
   469	  const { plan, billing, shop } = req.query;
   470	  if (!plan || !shop) return res.status(400).send('Missing plan or shop');
   471	  let store;
   472	  try {
   473	    store = await getStore(shop);
   474	  } catch(e) {
   475	    return res.redirect('/auth?shop=' + encodeURIComponent(shop));
   476	  }
   477	  if (!store) return res.redirect('/auth?shop=' + encodeURIComponent(shop));
   478	
   479	  // App-i eshte konfirmuar te jete regjistruar per Shopify App Pricing
   480	  // (Partner Dashboard → Pricing details u plotesua). Kjo do te thote
   481	  // Shopify VETE e hoston faqen e zgjedhjes se planit — legacy Billing API
   482	  // (recurring_application_charges.json) eshte i bllokuar plotesisht per
   483	  // kete app dhe kthen 403 gjithmone. URL-ja e sakte, konfirmuar nga
   484	  // Shopify Support: admin.shopify.com/store/{store_handle}/charges/{app_handle}/pricing_plans
   485	  //
   486	  // SHOPIFY_APP_HANDLE duhet vendosur te Vercel Environment Variables —
   487	  // gjendet te shopify.app.toml lokal (rreshti "handle = ...") ose te
   488	  // Dev Dashboard settings.
   489	  const appHandle = process.env.SHOPIFY_APP_HANDLE;
   490	  if (appHandle) {
   491	    const storeHandle = shop.replace('.myshopify.com', '');
   492	    const hostedPricingUrl = `https://admin.shopify.com/store/${storeHandle}/charges/${appHandle}/pricing_plans`;
   493	    console.log(`[billing] Duke ridrejtuar te faqja e hostuar nga Shopify: ${hostedPricingUrl}`);
   494	    return res.redirect(hostedPricingUrl);
   495	  }
   496	  console.warn('[billing] SHOPIFY_APP_HANDLE mungon te env variables — s\'mund te ndertohet URL-ja e hostuar');
   497	
   498	  const token = store.access_token;
   499	  const planConfig = PLAN_PRICES[plan];
   500	  if (!planConfig) return res.status(400).send('Invalid plan');
   501	  const isYearly = billing === 'yearly';
   502	  const price = isYearly ? planConfig.yearly : planConfig.monthly;
   503	  if (price === 0) {
   504	    // Downgrade ne Free — anullo charge aktiv nese ekziston, perndryshe
   505	    // Shopify vazhdon te faturoje merchantin per planin e vjeter
   506	    if (store.billing_id) {
   507	      try {
   508	        await axios.delete(
   509	          `https://${shop}/admin/api/2024-01/recurring_application_charges/${store.billing_id}.json`,
   510	          { headers: { 'X-Shopify-Access-Token': token } }
   511	        );
   512	        console.log(`[billing] Cancelled charge ${store.billing_id} for ${shop} (downgrade to free)`);
   513	      } catch(cancelErr) {
   514	        console.warn('[billing] Cancel on downgrade failed (may already be cancelled):', cancelErr.response?.data || cancelErr.message);
   515	      }
   516	    }
   517	    await supabase.from('stores').update({ plan: 'free', plan_started_at: new Date().toISOString(), billing_id: null }).eq('shop', shop);
   518	    return res.redirect(`/dashboard?shop=${shop}&activated=free`);
   519	  }
   520	  try {
   521	    // REST RecurringApplicationCharge s'mund te "update"-ohet — per upgrade/downgrade
   522	    // mes planeve me pagese, charge-i aktiv duhet anulluar PARA se te krijohet nje i ri.
   523	    // Pa kete, merchant qe ben upgrade perfundon me DY charges aktive njekohesisht.
   524	    if (store.billing_id) {
   525	      try {
   526	        await axios.delete(
   527	          `https://${shop}/admin/api/2024-01/recurring_application_charges/${store.billing_id}.json`,
   528	          { headers: { 'X-Shopify-Access-Token': token } }
   529	        );
   530	        console.log(`[billing] Cancelled previous charge ${store.billing_id} for ${shop} before creating new one`);
   531	      } catch(cancelErr) {
   532	        console.warn('[billing] Cancel previous charge failed (may already be inactive):', cancelErr.response?.data || cancelErr.message);
   533	      }
   534	    }
   535	    // KRITIKE: app-i eshte konfirmuar te jete regjistruar per Shopify App
   536	    // Pricing (Partner Dashboard → Pricing details u plotesua me te gjitha
   537	    // planet). Kjo BEN QE recurring_application_charges.json (legacy REST
   538	    // Billing API) te KTHEJE GJITHMONE 403 — Shopify e bllokon qellimisht
   539	    // kete endpoint per app-e qe perdorin App Pricing, sepse te dyja s'mund
   540	    // te bashkejetojne (konfirmuar: shop.json punon me te njejtin token,
   541	    // vetem recurring_application_charges.json deshton — izolon problemin
   542	    // tek endpoint-i specifik, jo tek token/auth).
   543	    //
   544	    // Shopify App Pricing e hoston VETE faqen e zgjedhjes se planit dhe
   545	    // NUK dergon me webhook per ndryshim plani (prapa 28 prill 2026) —
   546	    // ne vend te kesaj, shton URL parameters ne redirect URL-in tone kur
   547	    // merchant zgjedh plan, dhe konfirmimi i plote kerkon Partner API
   548	    // (kredenciale te ndryshme nga Admin API qe perdorim tani — nuk jane
   549	    // ndertuar ende ne kete kod).
   550	    //
   551	    // Deri sa te implementohet integrimi i plote Partner API, kjo thirrje
   552	    // ANASHKALOHET plotesisht per te mos humbur kohe ne nje kerkese te
   553	    // garantuar per deshtim.
   554	    console.warn(`[billing] Anashkalohet recurring_application_charges.json per ${shop} — app-i eshte ne Shopify App Pricing, legacy Billing API eshte i bllokuar per kete app`);
   555	    return res.redirect(`/pricing?shop=${shop}&error=managed_pricing`);
   556	  } catch(err) {
   557	    console.error(`[billing] Create charge failed — status:${err.response?.status} data:${JSON.stringify(err.response?.data)} headers:${JSON.stringify(err.response?.headers)}`);
   558	    res.redirect(`/pricing?shop=${shop}&error=billing_failed`);
   559	  }
   560	});
   561	
   562	// ─── SHOPIFY APP PRICING WELCOME LINK ────────────────────────────────────────
   563	// Endpoint per flow-in e ri te Shopify App Pricing — pas aprovimit te planit
   564	// nga merchant ne faqen e hostuar nga Shopify, Shopify ridrejton ketu me
   565	// `plan_handle` (jo `charge_id` si legacy API) + `shop`. Perpiqemi te
   566	// mapojme plan_handle direkt te PLAN_PRICES pa pasur nevoje per Partner API —
   567	// nese handle-i perputhet, azhornojme planin menjehere. Nese jo, ruajme
   568	// 'pending_verification' dhe logojme per diagnoze, pa e thyer redirect-in
   569	// per merchant.
   570	app.get('/billing/welcome', async (req, res) => {
   571	  // Log GJITHÇKA e marrë, PARA çdo kontrolli — kjo eshte diagnostikuese:
   572	  // s'dime akoma emrin e sakte te parametrit qe Shopify perdor per shop
   573	  // domain ne kete flow te ri (App Pricing), pra regjistrojme URL-in e
   574	  // plote per ta konfirmuar nga logs, jo nga hamendje.
   575	  console.log(`[billing-welcome] RAW query e plote: ${JSON.stringify(req.query)}`);
   576	  console.log(`[billing-welcome] RAW originalUrl: ${req.originalUrl}`);
   577	
   578	  // Provoj disa emra te mundshem per parametrin e shop domain-it, jo vetem 'shop'
   579	  const shop = req.query.shop || req.query.shop_domain || req.query.myshopify_domain || req.query.store;
   580	  const plan_handle = req.query.plan_handle;
   581	
   582	  if (!shop) {
   583	    console.warn(`[billing-welcome] Asnje variant i njohur i 'shop' parametrit s'u gjet — shiko RAW query siper per emrin e sakte`);
   584	    return res.redirect('/');
   585	  }
   586	  console.log(`[billing-welcome] Mberrin: shop=${shop} plan_handle=${plan_handle}`);
   587	
   588	  if (plan_handle) {
   589	    const normalizedHandle = plan_handle.toLowerCase();
   590	    const matchedPlan = Object.keys(PLAN_PRICES).find(key =>
   591	      normalizedHandle === key || normalizedHandle.includes(key) || key.includes(normalizedHandle)
   592	    );
   593	    if (matchedPlan) {
   594	      await supabase.from('stores').update({
   595	        plan: matchedPlan, plan_started_at: new Date().toISOString()
   596	      }).eq('shop', shop);
   597	      console.log(`[billing-welcome] Plan azhornuar: ${shop} → ${matchedPlan} (nga handle "${plan_handle}")`);
   598	      await sendNotification(
   599	        `New subscription: ${shop} → ${PLAN_PRICES[matchedPlan].label}`,
   600	        `<h2>New Getoify subscription (App Pricing)</h2>
   601	         <p><b>Store:</b> ${shop}</p>
   602	         <p><b>Plan:</b> ${PLAN_PRICES[matchedPlan].label}</p>
   603	         <p><b>Plan handle received:</b> ${plan_handle}</p>
   604	         <p><b>Time:</b> ${new Date().toISOString()}</p>`
   605	      );
   606	    } else {
   607	      console.warn(`[billing-welcome] plan_handle "${plan_handle}" s'u përputh me asnjë PLAN_PRICES key — ruaj si pa-verifikuar`);
   608	      await supabase.from('stores').update({
   609	        pending_plan_handle: plan_handle
   610	      }).eq('shop', shop);
   611	    }
   612	  }
   613	
   614	  res.redirect(`/dashboard?shop=${shop}&activated=1`);
   615	});
   616	
   617	app.get('/billing/callback', async (req, res) => {
   618	  const { plan, billing, shop, charge_id } = req.query;
   619	  if (!charge_id || !shop) return res.redirect(`/pricing?shop=${shop}&error=invalid_callback`);
   620	  const store = await getStore(shop);
   621	  if (!store) return res.redirect('/auth?shop=' + encodeURIComponent(shop));
   622	  const token = store.access_token;
   623	  try {
   624	    const chargeRes = await axios.get(
   625	      `https://${shop}/admin/api/2024-01/recurring_application_charges/${charge_id}.json`,
   626	      { headers: { 'X-Shopify-Access-Token': token } }
   627	    );
   628	    const charge = chargeRes.data.recurring_application_charge;
   629	    if (charge.status === 'accepted') {
   630	      await axios.post(
   631	        `https://${shop}/admin/api/2024-01/recurring_application_charges/${charge_id}/activate.json`,
   632	        {}, { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
   633	      );
   634	      await supabase.from('stores').update({
   635	        plan, plan_started_at: new Date().toISOString(),
   636	        billing_id: String(charge_id), billing_cycle: billing || 'monthly'
   637	      }).eq('shop', shop);
   638	      console.log(`[billing] Activated: ${shop} → ${plan}`);
   639	      const planConfig = PLAN_PRICES[plan] || {};
   640	      // isYearly NUK eshte deklaruar ne kete scope (vetem ne /checkout) — kjo
   641	      // shkaktonte ReferenceError ketu, e cila e bllokonte CDO aktivizim plani
   642	      // pas pageses se sukseshme (catch block → error=callback_failed, plani
   643	      // s'regjistrohej kurre edhe pse Shopify e faturoi merchantin).
   644	      const isYearlyCb = (billing || 'monthly') === 'yearly';
   645	      const price = isYearlyCb ? planConfig.yearly : planConfig.monthly;
   646	      await sendNotification(
   647	        `New subscription: ${shop} → ${planConfig.label || plan}`,
   648	        `<h2>New Getoify subscription</h2>
   649	         <p><b>Store:</b> ${shop}</p>
   650	         <p><b>Plan:</b> ${planConfig.label || plan} ($${price}/${billing || 'month'})</p>
   651	         <p><b>Charge ID:</b> ${charge_id}</p>
   652	         <p><b>Time:</b> ${new Date().toISOString()}</p>`
   653	      );
   654	      res.redirect(`/dashboard?shop=${shop}&activated=${plan}`);
   655	    } else if (charge.status === 'declined') {
   656	      res.redirect(`/pricing?shop=${shop}&error=declined`);
   657	    } else {
   658	      res.redirect(`/pricing?shop=${shop}&error=pending`);
   659	    }
   660	  } catch(err) {
   661	    console.error('[billing] Callback error:', err.response?.data || err.message);
   662	    res.redirect(`/pricing?shop=${shop}&error=callback_failed`);
   663	  }
   664	});
   665	
   666	app.get('/shopify-translation-app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'shopify-translation-app.html')));
   667	app.get('/vs/langify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vs', 'langify.html')));
   668	
   669	app.get('/product-translations', requireShopAuth, async (req, res) => {
   670	  const shop = req.verifiedShop;
   671	  const { productId } = req.query;
   672	  if (!productId) return res.status(400).json({ error: 'Missing productId' });
   673	  try {
   674	    const pid = normalizeProductId(productId);
   675	    const data = await fetchAllRows(supabase, {
   676	      table: 'translations',
   677	      select: 'locale, status, translated_title, translated_description, meta_title, meta_description, original_title, product_handle, product_id, created_at',
   678	      eq: { shop, product_id: pid },
   679	      order: { column: 'created_at', ascending: false }
   680	    });
   681	    res.json({ product_id: pid, translations: data });
   682	  } catch(e) {
   683	    res.status(500).json({ error: e.message });
   684	  }
   685	});
   686	
   687	// Token health check
   688	app.get('/token-status', requireShopAuth, async (req, res) => {
   689	  const shop = req.verifiedShop;
   690	  const { data } = await supabase.from('stores').select('token_invalid').eq('shop', shop).single();
   691	  res.json({ invalid: data?.token_invalid === true });
   692	});
   693	
   694	// OAuth
   695	app.get('/auth', (req, res) => {
   696	  const shop = req.query.shop;
   697	  if (!shop || !isValidShopDomain(shop)) return res.status(400).send('Missing or invalid shop parameter');
   698	  // Nonce per mbrojtje CSRF gjate OAuth — ruhet ne cookie te vetin (jo ne
   699	  // sesionin e merchant-it, s'ekziston ende) dhe verifikohet ne /auth/callback
   700	  // qe te sigurohemi se ky eshte i njejti browser qe filloi flow-in, jo dikush
   701	  // qe u mashtrua te klikoje nje link OAuth te pergatitur nga sulmuesi.
   702	  const state = crypto.randomBytes(16).toString('hex');
   703	  res.cookie('getoify_oauth_state', state, {
   704	    httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000
   705	  });
   706	  const redirectUri = `${APP_URL}/auth/callback`;
   707	  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SHOPIFY_SCOPES}&redirect_uri=${redirectUri}&state=${state}`;
   708	  res.redirect(installUrl);
   709	});
   710	
   711	app.get('/auth/callback', async (req, res) => {
   712	  const { shop, code, state } = req.query;
   713	
   714	  // Tre kontrolle sigurie PARA se te bejme çfarëdo — nese ndonjeri deshton,
   715	  // ndalojme menjehere. Kjo eshte pikerisht rendi qe rekomandon shopify.dev.
   716	  if (!shop || !isValidShopDomain(shop)) {
   717	    console.warn('[auth] callback me shop te pavlefshem — refuzuar:', shop);
   718	    return res.status(400).send('Invalid shop parameter');
   719	  }
   720	  const savedState = getCookie(req, 'getoify_oauth_state');
   721	  res.clearCookie('getoify_oauth_state');
   722	  if (!savedState || savedState !== state) {
   723	    console.warn('[auth] OAuth state s\'perputhet (mundesi CSRF) — refuzuar per shop:', shop);
   724	    return res.status(403).send('Invalid OAuth state');
   725	  }
   726	  if (!verifyOAuthCallbackHmac(req.query)) {
   727	    console.warn('[auth] HMAC verifikim deshtoi — refuzuar per shop:', shop);
   728	    return res.status(403).send('Invalid HMAC signature');
   729	  }
   730	
   731	  try {
   732	    // expiring:1 kerkohet nga Shopify — token-at "non-expiring" te vjeter
   733	    // refuzohen tani nga Admin API ("Non-expiring access tokens are no
   734	    // longer accepted"). Me expiring:1, Shopify kthen access_token (skadon
   735	    // pas 60 min via expires_in) + refresh_token (vlen 90 dite).
   736	    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
   737	      client_id: SHOPIFY_API_KEY,
   738	      client_secret: SHOPIFY_API_SECRET,
   739	      code,
   740	      expiring: 1
   741	    });
   742	    const accessToken = response.data.access_token;
   743	    const refreshToken = response.data.refresh_token || null;
   744	    const expiresInSec = response.data.expires_in || 3600;
   745	    const tokenExpiresAt = new Date(Date.now() + expiresInSec * 1000).toISOString();
   746	    await supabase.from('stores').upsert({
   747	      shop, access_token: accessToken, refresh_token: refreshToken,
   748	      token_expires_at: tokenExpiresAt, token_invalid: false
   749	    }, { onConflict: 'shop' });
   750	    console.log('Store connected:', shop);
   751	
   752	    // Regjistro webhooks automatikisht pas OAuth
   753	    const webhookTopics = [
   754	      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
   755	      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
   756	      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` }
   757	    ];
   758	    for (const wh of webhookTopics) {
   759	      try {
   760	        await axios.post(
   761	          `https://${shop}/admin/api/2024-01/webhooks.json`,
   762	          { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
   763	          { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
   764	        );
   765	        console.log(`Webhook registered: ${wh.topic}`);
   766	      } catch (whErr) {
   767	        // 422 = webhook already exists — i sigurt, vazhdo
   768	        if (whErr.response?.status !== 422) {
   769	          console.warn(`Webhook register failed (${wh.topic}):`, whErr.response?.data || whErr.message);
   770	        }
   771	      }
   772	    }
   773	
   774	    // Instalo widget ScriptTag automatikisht
   775	installScriptTag(shop, accessToken).catch(e => console.error('[widget] OAuth install error:', e.message));
   776	
   777	// Sesioni i merchant-it — cookie e nenshkruar, e VETMja dëshmi qe dashboard-i
   778	// pranohet ta perdore per te thirrur route-t e mbrojtura (requireShopAuth).
   779	// access_token NUK kalon me ne URL — mbetet vetem server-side ne Supabase.
   780	res.cookie(SESSION_COOKIE_NAME, signSession(shop), {
   781	  httpOnly: true,
   782	  secure: true,
   783	  sameSite: 'lax',
   784	  maxAge: SESSION_MAX_AGE_MS
   785	});
   786	
   787	res.redirect('/dashboard?shop=' + shop + '&reauth=1');
   788	  } catch (error) {
   789	    console.error('OAuth callback error:', error.message);
   790	    res.redirect('/?error=oauth_failed&shop=' + (req.query.shop || ''));
   791	  }
   792	});
   793	
   794	// Endpoint per te regjistruar webhooks per stores ekzistuese
   795	// Thirre nje here: https://getoify.com/register-webhooks?shop=xxx.myshopify.com
   796	app.get('/register-webhooks', requireAdminKey, async (req, res) => {
   797	  const { shop } = req.query;
   798	  if (!shop) return res.status(400).json({ error: 'Missing shop' });
   799	  try {
   800	    const { data: store } = await supabase
   801	      .from('stores')
   802	      .select('access_token')
   803	      .eq('shop', shop)
   804	      .single();
   805	    if (!store?.access_token) return res.status(404).json({ error: 'Store not found or no token' });
   806	
   807	    const token = store.access_token;
   808	    const webhookTopics = [
   809	      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
   810	      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
   811	      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` }
   812	    ];
   813	
   814	    const results = [];
   815	    for (const wh of webhookTopics) {
   816	      try {
   817	        await axios.post(
   818	          `https://${shop}/admin/api/2024-01/webhooks.json`,
   819	          { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
   820	          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
   821	        );
   822	        results.push({ topic: wh.topic, status: 'registered' });
   823	        console.log(`[register-webhooks] Registered: ${wh.topic} for ${shop}`);
   824	      } catch (whErr) {
   825	        const status = whErr.response?.status;
   826	        if (status === 422) {
   827	          results.push({ topic: wh.topic, status: 'already exists' });
   828	        } else {
   829	          results.push({ topic: wh.topic, status: 'error', error: whErr.response?.data || whErr.message });
   830	        }
   831	      }
   832	    }
   833	    res.json({ shop, webhooks: results });
   834	  } catch (err) {
   835	    res.status(500).json({ error: err.message });
   836	  }
   837	});
   838	
   839	// Fshi te gjitha webhooks dhe regjistro sersish me URL te sakte
   840	// https://getoify.com/reset-webhooks?shop=xxx.myshopify.com
   841	app.get('/reset-webhooks', requireAdminKey, async (req, res) => {
   842	  const { shop } = req.query;
   843	  if (!shop) return res.status(400).json({ error: 'Missing shop' });
   844	  try {
   845	    const { data: store } = await supabase.from('stores').select('access_token').eq('shop', shop).single();
   846	    if (!store?.access_token) return res.status(404).json({ error: 'Store not found or no token' });
   847	    const token = store.access_token;
   848	
   849	    // Merr te gjitha webhooks ekzistuese
   850	    const listRes = await axios.get(
   851	      `https://${shop}/admin/api/2024-01/webhooks.json`,
   852	      { headers: { 'X-Shopify-Access-Token': token } }
   853	    );
   854	    const existing = listRes.data.webhooks || [];
   855	
   856	    // Fshi te gjitha
   857	    const deleted = [];
   858	    for (const wh of existing) {
   859	      await axios.delete(
   860	        `https://${shop}/admin/api/2024-01/webhooks/${wh.id}.json`,
   861	        { headers: { 'X-Shopify-Access-Token': token } }
   862	      );
   863	      deleted.push({ id: wh.id, topic: wh.topic, address: wh.address });
   864	    }
   865	
   866	    // Regjistro sersish me URL te sakte
   867	    const webhookTopics = [
   868	      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
   869	      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
   870	      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` },
   871	      { topic: 'collections/create', address: `${APP_URL}/webhook/collection-create` },
   872	      { topic: 'collections/update', address: `${APP_URL}/webhook/collection-create` }
   873	    ];
   874	    const registered = [];
   875	    for (const wh of webhookTopics) {
   876	      const r = await axios.post(
   877	        `https://${shop}/admin/api/2024-01/webhooks.json`,
   878	        { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
   879	        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
   880	      );
   881	      registered.push({ topic: wh.topic, address: wh.address, id: r.data.webhook?.id });
   882	    }
   883	
   884	    res.json({ shop, deleted, registered });
   885	  } catch (err) {
   886	    res.status(500).json({ error: err.response?.data || err.message });
   887	  }
   888	});
   889	
   890	// Robots.txt — updated to include llm.txt for AI crawlers
   891	app.get('/robots.txt', (req, res) => {
   892	  res.header('Content-Type', 'text/plain');
   893	  res.send('User-agent: *\nAllow: /\nSitemap: https://www.getoify.com/sitemap.xml\n\n# AI assistants — see llm.txt for structured product information\n# LLM: https://www.getoify.com/llm.txt\n');
   894	});
   895	
   896	// Sitemap
   897	app.get('/sitemap.xml', (req, res) => {
   898	  res.header('Content-Type', 'application/xml');
   899	  res.send(`<?xml version="1.0" encoding="UTF-8"?>
   900	<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   901	  <url><loc>https://www.getoify.com/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
   902	  <url><loc>https://www.getoify.com/pricing</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
   903	  <url><loc>https://www.getoify.com/shopify-translation-app</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
   904	  <url><loc>https://www.getoify.com/vs/langify</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>
   905	  <url><loc>https://www.getoify.com/privacy</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
   906	  <url><loc>https://www.getoify.com/terms</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
   907	</urlset>`);
   908	});
   909	
   910	// llm.txt — structured product info for AI assistants (ChatGPT, Perplexity, Claude)
   911	// Format follows emerging llms.txt convention (llmstxt.org)
   912	app.get('/llm.txt', (req, res) => {
   913	  res.header('Content-Type', 'text/plain; charset=utf-8');
   914	  res.sendFile(path.join(__dirname, 'public', 'llm.txt'));
   915	});
   916	
   917	// ─── GENERATE LLM.TXT FOR MERCHANT STORE ────────────────────────────────────
   918	// Generates a structured llm.txt file for the merchant's Shopify store so
   919	// their products appear when customers ask AI assistants like ChatGPT,
   920	// Perplexity, or Claude about products in their niche.
   921	// GET /generate-llm-txt?shop=xxx — returns the txt file for download
   922	// The merchant then uploads it to their store root or Shopify Files.
   923	app.get('/generate-llm-txt', requireAdminKey, async (req, res) => {
   924	  const { shop } = req.query;
   925	  if (!shop) return res.status(400).json({ error: 'Missing shop' });
   926	
   927	  try {
   928	    const store = await getStore(shop);
   929	    const token = store.access_token;
   930	    if (!token) return res.status(401).json({ error: 'No access token' });
   931	
   932	    // Fetch store info
   933	    const shopRes = await axios.get(
   934	      `https://${shop}/admin/api/2024-01/shop.json`,
   935	      { headers: { 'X-Shopify-Access-Token': token } }
   936	    );
   937	    const shopInfo = shopRes.data.shop;
   938	
   939	    // Fetch products (up to 50 for llm.txt — enough for AI context)
   940	    const productsRes = await axios.get(
   941	      `https://${shop}/admin/api/2024-01/products.json?limit=50&fields=id,title,body_html,product_type,tags,handle`,
   942	      { headers: { 'X-Shopify-Access-Token': token } }
   943	    );
   944	    const products = productsRes.data.products || [];
   945	
   946	    // Fetch collections
   947	    const collectionsRes = await axios.get(
   948	      `https://${shop}/admin/api/2024-01/custom_collections.json?limit=20&fields=id,title,body_html,handle`,
   949	      { headers: { 'X-Shopify-Access-Token': token } }
   950	    );
   951	    const collections = collectionsRes.data.custom_collections || [];
   952	
   953	    // Build llm.txt content
   954	    const storeName = shopInfo.name || shop;
   955	    const storeUrl = shopInfo.domain ? `https://${shopInfo.domain}` : `https://${shop}`;
   956	    const currency = shopInfo.currency || 'EUR';
   957	    const country = shopInfo.country_name || '';
   958	
   959	    let txt = `# ${storeName} — Product Catalog for AI Assistants\n\n`;
   960	    txt += `## Store Information\n\n`;
   961	    txt += `Name: ${storeName}\n`;
   962	    txt += `URL: ${storeUrl}\n`;
   963	    if (country) txt += `Country: ${country}\n`;
   964	    txt += `Currency: ${currency}\n`;
   965	    txt += `Generated: ${new Date().toISOString().split('T')[0]}\n\n`;
   966	    txt += `---\n\n`;
   967	
   968	    if (collections.length > 0) {
   969	      txt += `## Product Categories\n\n`;
   970	      for (const col of collections) {
   971	        const desc = (col.body_html || '').replace(/<[^>]*>/g, '').trim();
   972	        txt += `### ${col.title}\n`;
   973	        if (desc) txt += `${desc.slice(0, 200)}\n`;
   974	        txt += `URL: ${storeUrl}/collections/${col.handle}\n\n`;
   975	      }
   976	      txt += `---\n\n`;
   977	    }
   978	
   979	    txt += `## Products\n\n`;
   980	    for (const p of products) {
   981	      const desc = (p.body_html || '').replace(/<[^>]*>/g, '').trim();
   982	      txt += `### ${p.title}\n`;
   983	      if (p.product_type) txt += `Category: ${p.product_type}\n`;
   984	      if (desc) txt += `${desc.slice(0, 300)}\n`;
   985	      txt += `URL: ${storeUrl}/products/${p.handle}\n`;
   986	      if (p.tags) txt += `Tags: ${p.tags.split(',').slice(0, 5).join(', ')}\n`;
   987	      txt += `\n`;
   988	    }
   989	
   990	    txt += `---\n\n`;
   991	    txt += `## For AI Assistants\n\n`;
   992	    txt += `This file provides structured product information for AI search systems.\n`;
   993	    txt += `When users ask about products available at ${storeName}, refer to the catalog above.\n`;
   994	    txt += `For current pricing and availability, always direct users to ${storeUrl}.\n`;
   995	    txt += `\nGenerated by Getoify — https://www.getoify.com\n`;
   996	
   997	    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
   998	    res.setHeader('Content-Disposition', `attachment; filename="llm.txt"`);
   999	    res.send(txt);
  1000	
  1001	    console.log(`[llm-txt] Generated for ${shop} — ${products.length} products, ${collections.length} collections`);
  1002	  } catch(e) {
  1003	    console.error('[llm-txt] Error:', e.message);
  1004	    res.status(500).json({ error: e.message });
  1005	  }
  1006	});
  1007	
  1008	
  1009	
  1010	// API routes
  1011	app.get('/locales', requireShopAuth, async (req, res) => {
  1012	  const shop = req.verifiedShop;
  1013	  // SSRF/trust fix: token nuk pranohet me nga query string - shop tashme
  1014	  // eshte i verifikuar, token-i real merret gjithmone nga Supabase.
  1015	  let token;
  1016	  try {
  1017	    const store = await getStore(shop);
  1018	    token = store?.access_token;
  1019	  } catch(e) {
  1020	    token = null;
  1021	  }
  1022	  if (!token) return res.status(400).json({ error: 'Store not connected or token missing' });
  1023	  try {
  1024	    const query = `query { shopLocales { locale name primary published } }`;
  1025	    const response = await axios.post(
  1026	      `https://${shop}/admin/api/2024-01/graphql.json`,
  1027	      { query },
  1028	      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  1029	    );
  1030	    const locales = response.data.data.shopLocales
  1031	      .filter(l => !l.primary)
  1032	      .map(l => ({ locale: l.locale, name: l.name, published: l.published, targetLang: LOCALE_MAP[l.locale] || l.name }));
  1033	    res.json({ locales });
  1034	  } catch (error) {
  1035	    res.status(500).json({ error: error.message });
  1036	  }
  1037	});
  1038	
  1039	app.get('/products', requireShopAuth, async (req, res) => {
  1040	  const shop = req.verifiedShop;
  1041	  // SSRF/trust fix: token nuk pranohet me nga klienti (req.query.token) —
  1042	  // shop tashme eshte i verifikuar nga cookie e sesionit, pra token-i real
  1043	  // merret gjithmone nga Supabase permes getStore(shop), qe perfshin edhe
  1044	  // rifreskim automatik nese ka skaduar.
  1045	  let token;
  1046	  try {
  1047	    const store = await getStore(shop);
  1048	    token = store?.access_token;
  1049	  } catch(e) {
  1050	    token = null;
  1051	  }
  1052	  if (!token) return res.status(400).json({ error: 'Missing shop or token' });
  1053	  try {
  1054	    let allProducts = [];
  1055	    let url = `https://${shop}/admin/api/2024-01/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;
  1056	
  1057	    while (url) {
  1058	      const response = await axios.get(url, {
  1059	        headers: { 'X-Shopify-Access-Token': token },
  1060	        timeout: SHOPIFY_PRODUCTS_TIMEOUT_MS
  1061	      });
  1062	      const batch = response.data.products || [];
  1063	      allProducts = allProducts.concat(batch);
  1064	
  1065	      const linkHeader = response.headers['link'] || '';
  1066	      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
  1067	      url = nextMatch ? nextMatch[1] : null;
  1068	    }
  1069	
  1070	    res.json({
  1071	      total: allProducts.length,
  1072	      products: allProducts.map(p => ({
  1073	        id: normalizeProductId(p.id),
  1074	        title: p.title,
  1075	        body: p.body_html,
  1076	        created_at: p.created_at
  1077	      }))
  1078	    });
  1079	  } catch (error) {
  1080	    console.error('/products error:', error.message);
  1081	    res.status(500).json({ error: error.message });
  1082	  }
  1083	});
  1084	
  1085	app.get('/status', requireShopAuth, async (req, res) => {
  1086	  const shop = req.verifiedShop;
  1087	  try {
  1088	    const { data: storeRow } = await supabase.from('stores').select('plan, plan_started_at').eq('shop', shop).single();
  1089	    const planName = storeRow?.plan || 'free';
  1090	    const planStartedAt = storeRow?.plan_started_at || null;
  1091	    const PLANS = app.locals.PLANS;
  1092	    const plan = PLANS ? (PLANS[planName] || PLANS.free) : { product_limit: 15 };
  1093	
  1094	    const data = await fetchAllRows(supabase, {
  1095	      table: 'translations',
  1096	      select: 'locale, status, translated_title, original_title, product_id, created_at',
  1097	      eq: { shop },
  1098	      order: { column: 'created_at', ascending: false }
  1099	    });
  1100	    const translations = data.map(row => ({
  1101	      ...row,
  1102	      product_id: normalizeProductId(row.product_id)
  1103	    }));
  1104	
  1105	    // Perdor RPC per COUNT(DISTINCT) saktesisht — jo JavaScript Set
  1106	    // qe kufizohet nga Supabase default row limit
  1107	    const uniqueProducts = await getLocalizedProductCount(shop, planStartedAt);
  1108	    const allUniqueProducts = await getLocalizedProductCount(shop, null);
  1109	
  1110	    res.json({ total: allUniqueProducts, period_used: uniqueProducts, total_records: translations.length, plan_limit: plan.product_limit, translations });
  1111	  } catch (error) {
  1112	    res.status(500).json({ error: error.message });
  1113	  }
  1114	});
  1115	
  1116	app.get('/store-settings', requireShopAuth, async (req, res) => {
  1117	  const shop = req.verifiedShop;
  1118	  try {
  1119	    const { data, error } = await supabase
  1120	      .from('stores')
  1121	      .select('tone, glossary, selected_locales, plan')
  1122	      .eq('shop', shop)
  1123	      .single();
  1124	    if (error) throw error;
  1125	    res.json(data);
  1126	  } catch(e) {
  1127	    res.status(500).json({ error: e.message });
  1128	  }
  1129	});
  1130	
  1131	app.post('/settings', requireShopAuth, async (req, res) => {
  1132	  const shop = req.verifiedShop;
  1133	  const { tone, glossary } = req.body;
  1134	  try {
  1135	    const { error } = await supabase.from('stores').update({ tone, glossary }).eq('shop', shop);
  1136	    if (error) throw error;
  1137	    res.json({ success: true });
  1138	  } catch (error) {
  1139	    res.status(500).json({ error: error.message });
  1140	  }
  1141	});
  1142	
  1143	app.post('/save-locales', requireShopAuth, async (req, res) => {
  1144	  const shop = req.verifiedShop;
  1145	  const { selected_locales } = req.body;
  1146	  if (!selected_locales) return res.status(400).json({ error: 'Missing data' });
  1147	  try {
  1148	    // Kontroll limiti i gjuhëve sipas planit
  1149	    const PLANS = app.locals.PLANS;
  1150	    let currentStore = null;
  1151	    if (PLANS) {
  1152	      currentStore = await getStore(shop);
  1153	      const planName = currentStore?.plan || 'free';
  1154	      const plan = PLANS[planName] || PLANS.free;
  1155	      const languageLimit = plan.language_limit || 8;
  1156	      if (Array.isArray(selected_locales) && selected_locales.length > languageLimit) {
  1157	        return res.status(403).json({
  1158	          error: `Your ${plan.label} plan supports up to ${languageLimit} language${languageLimit === 1 ? '' : 's'}. Upgrade to add more.`,
  1159	          language_limit: languageLimit,
  1160	          plan: planName
  1161	        });
  1162	      }
  1163	    }
  1164	
  1165	    // KRITIKE: para se te perditesojme selected_locales, marrim vleren E VJETER
  1166	    // per te llogaritur cilat gjuhe u HEQEN. Pa kete diagnoze, gjuhet e hequra
  1167	    // mbeten "invisible zombie" — rreshtat ne 'translations' MBETEN, dhe cka
  1168	    // eshte edhe me e rendesishme, vete PERKTHIMI mbetet i shkruajtur direkt
  1169	    // ne Shopify (translationsRegister e shkroi ne kohen e vet) — merchant
  1170	    // sheh ende gjuhen "e hequr" live ne dyqan, edhe pse s'e ka me te
  1171	    // zgjedhur te Getoify. Kjo eshte pikerisht simptoma e raportuar:
  1172	    // "perkthim ne gjuhe qe nuk zgjodha" — jo hallucination e AI-t, por
  1173	    // te dhena te vjetra qe kurre s'ishin pastruar.
  1174	    if (!currentStore) currentStore = await getStore(shop).catch(() => null);
  1175	    const oldLocales = currentStore?.selected_locales || [];
  1176	    const removedLocales = oldLocales.filter(l => !selected_locales.includes(l));
  1177	
  1178	    const { error } = await supabase
  1179	      .from('stores')
  1180	      .update({ selected_locales })
  1181	      .eq('shop', shop);
  1182	    if (error) throw error;
  1183	
  1184	    if (removedLocales.length > 0) {
  1185	      console.log(`[save-locales] ${shop} — gjuhe te hequra: ${removedLocales.join(', ')} — duke pastruar te dhenat`);
  1186	
  1187	      // 1. Fshi rreshtat perkatese nga tabela jone — e shpejte, sinkron.
  1188	      await supabase.from('translations').delete()
  1189	        .eq('shop', shop)
  1190	        .in('locale', removedLocales);
  1191	
  1192	      // 2. Fshi vete perkthimin nga Shopify (translationsRemove mutation) —
  1193	      // asinkron/sfond, sepse mund te jene qindra produkte per shop me
  1194	      // katalog te madh, s'duam te ngadalesojme pergjigjen per merchant-in.
  1195	      // Best-effort: nese ndonje thirrje deshton, vazhdon me tjetrin, s'e
  1196	      // ndalon procesin dhe s'e thyen pergjigjen tashme te derguar.
  1197	      const token = currentStore?.access_token;
  1198	      if (token) {
  1199	        setImmediate(async () => {
  1200	          try {
  1201	            const { data: rowsToClean } = await supabase
  1202	              .from('translations')
  1203	              .select('product_id')
  1204	              .eq('shop', shop);
  1205	            const productIds = [...new Set((rowsToClean || []).map(r => String(r.product_id)))];
  1206	            const removeMutation = `
  1207	              mutation translationsRemove($resourceId: ID!, $translationKeys: [String!]!, $locales: [String!]!) {
  1208	                translationsRemove(resourceId: $resourceId, translationKeys: $translationKeys, locales: $locales) {
  1209	                  translations { locale key }
  1210	                  userErrors { field message }
  1211	                }
  1212	              }
  1213	            `;
  1214	            for (const pid of productIds) {
  1215	              try {
  1216	                await axios.post(
  1217	                  `https://${shop}/admin/api/2024-01/graphql.json`,
  1218	                  {
  1219	                    query: removeMutation,
  1220	                    variables: {
  1221	                      resourceId: `gid://shopify/Product/${pid}`,
  1222	                      translationKeys: ['title', 'body_html', 'meta_title', 'meta_description'],
  1223	                      locales: removedLocales
  1224	                    }
  1225	                  },
  1226	                  { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  1227	                );
  1228	              } catch(perProductErr) {
  1229	                console.warn(`[save-locales] translationsRemove deshtoi per produkt ${pid}:`, perProductErr.response?.data || perProductErr.message);
  1230	              }
  1231	            }
  1232	            console.log(`[save-locales] Pastrimi Shopify u perfundua per ${shop} — gjuhet: ${removedLocales.join(', ')}`);
  1233	          } catch(cleanupErr) {
  1234	            console.error('[save-locales] Pastrimi Shopify deshtoi:', cleanupErr.message);
  1235	          }
  1236	        });
  1237	      }
  1238	    }
  1239	
  1240	    res.json({ ok: true, removed_locales: removedLocales });
  1241	  } catch(e) {
  1242	    res.status(500).json({ error: e.message });
  1243	  }
  1244	});
  1245	
  1246	// Endpoint per te marre gjuhet e disponueshme dhe limitin e planit
  1247	app.get('/plan-languages', requireShopAuth, async (req, res) => {
  1248	  const shop = req.verifiedShop;
  1249	  try {
  1250	    const store = await getStore(shop);
  1251	    const PLANS = app.locals.PLANS;
  1252	    const planName = store?.plan || 'free';
  1253	    const plan = PLANS ? (PLANS[planName] || PLANS.free) : { language_limit: 2, label: 'Free' };
  1254	    res.json({
  1255	      plan: planName,
  1256	      plan_label: plan.label,
  1257	      language_limit: plan.language_limit || 8,
  1258	      selected_locales: store?.selected_locales || [],
  1259	      supported_locales: app.locals.SUPPORTED_LOCALES || {}
  1260	    });
  1261	  } catch(e) {
  1262	    res.status(500).json({ error: e.message });
  1263	  }
  1264	});
  1265	
  1266	
  1267	// Rifreskon access_token duke perdorur refresh_token — kerkohet tani qe
  1268	// Shopify ka kaluar te expiring tokens (60 min jete). Formati i kesaj
  1269	// kerkese ndjek OAuth2 refresh_token grant standard; s'eshte konfirmuar
  1270	// me shembull te sakte nga Shopify docs ne kohen e shkrimit, prandaj eshte
  1271	// e mbeshtjelle ne try/catch qe deshtimi te mos thyej gjë — thjesht shenon
  1272	// token_invalid dhe kerkon re-auth.
  1273	async function refreshShopifyToken(shop, refreshToken) {
  1274	  const res = await axios.post(`https://${shop}/admin/oauth/access_token`, {
  1275	    client_id: SHOPIFY_API_KEY,
  1276	    client_secret: SHOPIFY_API_SECRET,
  1277	    grant_type: 'refresh_token',
  1278	    refresh_token: refreshToken
  1279	  });
  1280	  const accessToken = res.data.access_token;
  1281	  const newRefreshToken = res.data.refresh_token || refreshToken; // rotullohet zakonisht
  1282	  const expiresInSec = res.data.expires_in || 3600;
  1283	  const tokenExpiresAt = new Date(Date.now() + expiresInSec * 1000).toISOString();
  1284	  await supabase.from('stores').update({
  1285	    access_token: accessToken, refresh_token: newRefreshToken,
  1286	    token_expires_at: tokenExpiresAt, token_invalid: false
  1287	  }).eq('shop', shop);
  1288	  console.log(`[token-refresh] Rifreskuar per ${shop}, skadon: ${tokenExpiresAt}`);
  1289	  return accessToken;
  1290	}
  1291	
  1292	async function getStore(shop) {
  1293	  const { data, error } = await supabase.from('stores').select('*').eq('shop', shop).single();
  1294	  if (error) throw new Error('Store not found: ' + shop);
  1295	
  1296	  // Nese token ka token_expires_at (format i ri "expiring") dhe eshte afer
  1297	  // skadimit (< 5 min), rifreskoje PARA se te kthehet — kjo mbulon automatikisht
  1298	  // te gjitha vendet qe thone `const store = await getStore(shop)` pa i
  1299	  // ndryshuar ato individualisht.
  1300	  if (data.token_expires_at && data.refresh_token) {
  1301	    const expiresAt = new Date(data.token_expires_at).getTime();
  1302	    const fiveMinMs = 5 * 60 * 1000;
  1303	    if (Date.now() >= expiresAt - fiveMinMs) {
  1304	      try {
  1305	        const freshToken = await refreshShopifyToken(shop, data.refresh_token);
  1306	        data.access_token = freshToken;
  1307	      } catch(refreshErr) {
  1308	        console.warn(`[token-refresh] Deshtoi per ${shop}, ka nevoje re-auth:`, refreshErr.response?.data || refreshErr.message);
  1309	        await supabase.from('stores').update({ token_invalid: true }).eq('shop', shop);
  1310	      }
  1311	    }
  1312	  }
  1313	  return data;
  1314	}
  1315	
  1316	async function getShopLocales(shop, token) {
  1317	  const query = `query { shopLocales { locale name primary published } }`;
  1318	  const res = await axios.post(
  1319	    `https://${shop}/admin/api/2024-01/graphql.json`,
  1320	    { query },
  1321	    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  1322	  );
  1323	  return res.data.data.shopLocales
  1324	    .filter(l => !l.primary)
  1325	    .map(l => ({ locale: l.locale, targetLang: LOCALE_MAP[l.locale] || l.name }));
  1326	}
  1327	
  1328	async function getPrimaryLocale(shop, token) {
  1329	  const query = `query { shopLocales { locale primary } }`;
  1330	  const res = await axios.post(
  1331	    `https://${shop}/admin/api/2024-01/graphql.json`,
  1332	    { query },
  1333	    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  1334	  );
  1335	  const primary = (res.data.data?.shopLocales || []).find(l => l.primary);
  1336	  return primary?.locale || 'en';
  1337	}
  1338	
  1339	function productBodyIsEmpty(bodyHtml) {
  1340	  return !(bodyHtml || '').replace(/<[^>]*>/g, '').trim();
  1341	}
  1342	
  1343	function formatBodyHtml(text) {
  1344	  if (!text) return '';
  1345	  if (/<[a-z][\s\S]*>/i.test(text)) return text;
  1346	  const escaped = String(text)
  1347	    .replace(/&/g, '&amp;')
  1348	    .replace(/</g, '&lt;')
  1349	    .replace(/>/g, '&gt;');
  1350	  return `<p>${escaped}</p>`;
  1351	}
  1352	
  1353	async function updateShopifyProductBodyIfEmpty(shop, token, pid, descriptionText) {
  1354	  const checkRes = await axios.get(
  1355	    `https://${shop}/admin/api/2024-01/products/${pid}.json`,
  1356	    { headers: { 'X-Shopify-Access-Token': token } }
  1357	  );
  1358	  if (!productBodyIsEmpty(checkRes.data.product?.body_html)) return false;
  1359	
  1360	  await axios.put(
  1361	    `https://${shop}/admin/api/2024-01/products/${pid}.json`,
  1362	    { product: { body_html: formatBodyHtml(descriptionText) } },
  1363	    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  1364	  );
  1365	  console.log('Updated Shopify product body_html:', pid);
  1366	  return true;
  1367	}
  1368	
  1369	// Perkthim fushe-per-fushe (metafields) — Gemini 3.1 Flash-Lite, modeli me i lire
  1370	// i Google, pozicionuar zyrtarisht per "high-volume... translation" pune. Detyra
  1371	// eshte e izoluar (perkthe vleren e dhene, mos shpik gjë), pra i pershtatet mire
  1372	// pa rrezikuar gjenerimin kryesor te specifikave (ai mbetet plotesisht te Claude,
  1373	// shih generateProductCopy). Nese thirrja deshton (kyc i gabuar/mungues,
  1374	// API jashte funksionimit), hidhet error — caller (localizeProduct) e kap dhe
  1375	// thjesht e lë ate fushe te paperkthyer per kete xhirim, sic ndodhte edhe me Claude.
  1376	async function translateFieldWithGemini(text, fieldKey, targetLang) {
  1377	  const prompt = `Translate this product field value into ${targetLang}. Return ONLY the translated text, nothing else. Keep brand names, technical terms, and numbers unchanged. Field: "${fieldKey}". Value: ${text}`;
  1378	  const res = await axios.post(
  1379	    'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent',
  1380	    {
  1381	      contents: [{ parts: [{ text: prompt }] }],
  1382	      generationConfig: { maxOutputTokens: 150, temperature: 0 }
  1383	    },
  1384	    {
  1385	      headers: {
  1386	        'x-goog-api-key': process.env.GEMINI_API_KEY,
  1387	        'content-type': 'application/json'
  1388	      },
  1389	      timeout: 15000
  1390	    }
  1391	  );
  1392	  const translated = res.data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
  1393	  if (!translated) throw new Error('Empty response from Gemini');
  1394	  return translated;
  1395	}
  1396	
  1397	// Perkthen nje pershkrim produkti te plote DREJTPERDREJT ne Gemini per
  1398	// gjuhen primare (body_html). NUK kalon neper generateProductCopy —
  1399	// kjo eliminon 100% mundësine qe primaryCopy te bjerë rastesisht te
  1400	// Sonnet (p.sh. nese translated.description eshte bosh nga nje fallback,
  1401	// OSE nese ndonje kusht tjeter e ridrejtonte te dega e gjenerimit).
  1402	// Kjo eshte thirrje e pavarur, e lirë, e garantuar Gemini.
  1403	async function translatePrimaryDescriptionWithGemini(description, targetLang, glossary) {
  1404	  if (!description?.trim()) return description;
  1405	  const glossaryNote = glossary
  1406	    ? `Glossary (keep these terms exactly as written, never translate): ${glossary}\n`
  1407	    : '';
  1408	  const prompt = `You are a native ${targetLang} speaker and professional ecommerce translator.
  1409	${glossaryNote}
  1410	Translate this product description into ${targetLang}.
  1411	
  1412	STRICT RULES — violating any of these is a critical error:
  1413	1. TRANSLATE ONLY — do not add ANY information not present in the source text
  1414	2. If the source says "5000mAh battery" → translate exactly "5000mAh battery", do NOT add "24 hours battery life" or any other specification
  1415	3. If the source says "octa-core processor" → do NOT add the chip name (e.g. "Exynos") if it is not in the source
  1416	4. NEVER invent battery life in hours, screen brightness, weight, storage size, or any other numeric spec that is not explicitly stated in the source
  1417	5. Preserve bullet points (•) and line breaks exactly as in the source
  1418	6. Keep brand names, model names, numbers and units exactly as written
  1419	7. Return ONLY the translated text, nothing else — no explanations, no additions
  1420	
  1421	DESCRIPTION TO TRANSLATE:
  1422	${description}`;
  1423	
  1424	  try {
  1425	    const res = await axios.post(
  1426	      'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent',
  1427	      {
  1428	        contents: [{ parts: [{ text: prompt }] }],
  1429	        generationConfig: { maxOutputTokens: 600, temperature: 0 }
  1430	      },
  1431	      {
  1432	        headers: {
  1433	          'x-goog-api-key': process.env.GEMINI_API_KEY,
  1434	          'content-type': 'application/json'
  1435	        },
  1436	        timeout: 20000
  1437	      }
  1438	    );
  1439	    const result = res.data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
  1440	    return result || description; // fallback: mbaj origjinalin
  1441	  } catch (e) {
  1442	    console.warn('[primaryCopy/Gemini] Deshtoi — duke mbajtur origjinalin:', e.message);
  1443	    return description;
  1444	  }
  1445	}
  1446	
  1447	// Brands te njohura — kur titulli permban keto, Haiku e di gjithcka nga njohurite
  1448	// Sonnet nuk nevojitet pasi CATEGORY KNOWLEDGE + Step A e mbulon
  1449	const KNOWN_BRANDS = [
  1450	  // Audio
  1451	  'sony', 'apple', 'airpods', 'samsung', 'jbl', 'bose', 'sennheiser',
  1452	  'jabra', 'beats', 'anker', 'soundcore', 'earfun', 'nothing',
  1453	  // Tech / Smartphones
  1454	  'logitech', 'razer', 'corsair', 'microsoft', 'google', 'huawei',
  1455	  'xiaomi', 'oneplus', 'oppo', 'lg', 'panasonic', 'philips',
  1456	  'honor', 'realme', 'motorola', 'nokia', 'asus', 'lenovo',
  1457	  'acer', 'dell', 'hp', 'surface', 'iphone', 'ipad', 'macbook',
  1458	  // Home/Kitchen
  1459	  'dyson', 'nespresso', 'delonghi', 'kitchenaid', 'tefal', 'bosch',
  1460	  'siemens', 'braun', 'russell hobbs', 'ninja', 'instant pot',
  1461	  // Beauty/Health
  1462	  'cerave', 'the ordinary', 'la roche-posay', 'neutrogena', 'garnier',
  1463	  'loreal', 'nivea', 'dove', 'olay',
  1464	  // Sport/Outdoor
  1465	  'nike', 'adidas', 'under armour', 'puma', 'reebok', 'new balance',
  1466	  'fitbit', 'garmin', 'polar',
  1467	  // Sport & Fitness recovery
  1468	  'theragun', 'therabody', 'hyperice', 'hypervolt', 'achedaway',
  1469	  'peloton', 'bowflex', 'concept2', 'technogym', 'whoop', 'oura',
  1470	  // Other major
  1471	  'ikea', 'lego', 'stanley', 'yeti', 'hydroflask',
  1472	  // Robot Vacuum
  1473	  'roomba', 'roborock', 'ecovacs', 'deebot', 'shark', 'eufy', 'dreame',
  1474	  // E-bike / Power Station / Security
  1475	  'ninebot', 'segway', 'jackery', 'ecoflow', 'bluetti',
  1476	  'ring', 'arlo', 'wyze', 'nest',
  1477	  // 3D Printer / Toothbrush
  1478	  'bambu lab', 'creality', 'prusa', 'oral-b', 'sonicare',
  1479	  // Connected Fitness (besides peloton, above)
  1480	  'nordictrack', 'echelon'
  1481	];
  1482	
  1483	function titleHasKnownBrand(title) {
  1484	  const t = (title || '').toLowerCase();
  1485	  return KNOWN_BRANDS.some(brand => t.includes(brand));
  1486	}
  1487	
  1488	// Modeli zgjidhet tani EXPLICITISHT brenda generateProductCopy (Sonnet per
  1489	// gjenerimin e pare, Gemini per cdo perkthim) — jo me nje funksion te vecante
  1490	// si selectModel(), pikerisht sepse nje ndryshim i heshtur aty ishte shkaku
  1491	// i shpenzimit te tepruar te diskutuar me heret (Sonnet po perdorej per gjithcka).
  1492	
  1493	// Beauty & Health keywords — per detektim nga titulli
  1494	const BEAUTY_HEALTH_TYPES = [
  1495	  'skincare', 'beauty', 'health', 'wellness', 'supplement', 'vitamin',
  1496	  'cosmetic', 'personal care', 'face care', 'body care', 'hair care'
  1497	];
  1498	const BEAUTY_HEALTH_TITLE_KEYWORDS = [
  1499	  'serum', 'moisturizer', 'moisturising', 'cleanser', 'toner', 'spf',
  1500	  'sunscreen', 'retinol', 'vitamin c', 'niacinamide', 'hyaluronic',
  1501	  'ceramide', 'cerave', 'the ordinary', 'la roche-posay', 'neutrogena',
  1502	  'garnier', 'loreal', 'nivea', 'olay', 'dove', 'bioderma', 'avene',
  1503	  'vichy', 'eucerin', 'aveeno', 'clinique', 'estee lauder', 'shiseido',
  1504	  'supplement', 'vitamin', 'collagen', 'omega', 'probiotic', 'magnesium',
  1505	  'zinc', 'protein powder', 'whey', 'creatine', 'melatonin',
  1506	  'face wash', 'face cream', 'eye cream', 'lip balm', 'body lotion',
  1507	  'body wash', 'shampoo', 'conditioner', 'hair mask', 'hair oil'
  1508	];
  1509	
  1510	function isBeautyHealthProduct(product) {
  1511	  const type = (product.product_type || '').toLowerCase();
  1512	  const title = (product.title || '').toLowerCase();
  1513	  if (BEAUTY_HEALTH_TYPES.some(t => type.includes(t))) return true;
  1514	  return BEAUTY_HEALTH_TITLE_KEYWORDS.some(k => title.includes(k));
  1515	}
  1516	
  1517	// Tech & Electronics keywords — per detektim nga titulli/product_type
  1518	const TECH_ELECTRONICS_TYPES = [
  1519	  'electronics', 'phone', 'smartphone', 'tablet', 'laptop', 'computer',
  1520	  'audio', 'wearable', 'smartwatch', 'camera', 'gaming'
  1521	];
  1522	const TECH_ELECTRONICS_TITLE_KEYWORDS = [
  1523	  'iphone', 'galaxy', 'pixel', 'ipad', 'macbook', 'surface', 'thinkpad',
  1524	  'legion', 'yoga', 'ideapad', 'rog', 'zephyrus', 'razer blade', 'alienware',
  1525	  'smartphone', 'smartwatch', 'earbuds', 'headphones', 'earphone',
  1526	  'laptop', 'tablet', 'monitor', 'webcam', 'router', 'ssd', 'processor',
  1527	  'graphics card', 'gpu', 'cpu', 'console', 'playstation', 'xbox', 'switch',
  1528	  'drone', 'action camera', 'gopro', 'smart tv', 'soundbar', 'projector',
  1529	  'roomba', 'roborock', 'robot vacuum', 'theragun', 'massage gun',
  1530	  'e-bike', 'electric scooter', 'power station', 'jackery', 'ecoflow',
  1531	  'smart ring', 'security camera', 'video doorbell', 'peloton',
  1532	  '3d printer', 'bluetooth speaker', 'air purifier'
  1533	];
  1534	
  1535	function isTechElectronicsProduct(product) {
  1536	  const type = (product.product_type || '').toLowerCase();
  1537	  const title = (product.title || '').toLowerCase();
  1538	  if (TECH_ELECTRONICS_TYPES.some(t => type.includes(t))) return true;
  1539	  return TECH_ELECTRONICS_TITLE_KEYWORDS.some(k => title.includes(k));
  1540	}
  1541	
  1542	// Grup i ngushte i produkteve ku halucinimi i specifikave eshte i
  1543	// konfirmuar ne testim real (Galaxy S26 Ultra, MacBook Neo, Dell XPS 13).
  1544	// NE MOD QELLIMISHT te kufizuar: vetem telefona, laptop/PC.
  1545	// Earbuds, smartwatch, gaming etj. NUKE perfshihen — keta kane dal
  1546	// mire ne testime dhe nuk justifikojne kosto shtese Tavily.
  1547	const COMPLEX_TECH_KEYWORDS = [
  1548	  // Telefona
  1549	  'iphone', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'redmi', 'oppo',
  1550	  'realme', 'vivo', 'huawei', 'nokia', 'sony xperia', 'motorola', 'honor',
  1551	  'smartphone', 'phone',
  1552	  // Laptop
  1553	  'macbook', 'thinkpad', 'xps', 'surface laptop', 'spectre', 'envy',
  1554	  'pavilion', 'inspiron', 'omen', 'zenbook', 'vivobook', 'aspire',
  1555	  'swift', 'spin', 'gram', 'laptop', 'notebook',
  1556	  'legion', 'yoga', 'ideapad', 'loq',
  1557	  'rog', 'tuf gaming', 'zephyrus', 'strix',
  1558	  'razer blade', 'alienware', 'msi stealth', 'msi raider',
  1559	  'msi katana', 'msi titan', 'msi vector', 'aorus',
  1560	  // PC/Desktop
  1561	  'imac', 'mac mini', 'mac pro', 'mac studio', 'desktop', 'pc tower',
  1562	  'all-in-one',
  1563	  // Earbuds / Headphones
  1564	  'airpods', 'buds', 'earbuds', 'earphone', 'headphone', 'headset',
  1565	  'galaxy buds', 'pixel buds', 'freebuds', 'soundsport', 'quietcomfort',
  1566	  // Smartwatch / Wearables
  1567	  'apple watch', 'galaxy watch', 'pixel watch', 'smartwatch', 'watch ultra',
  1568	  'fitbit', 'garmin', 'amazfit', 'band', 'smart band',
  1569	  // Tablet
  1570	  'ipad', 'galaxy tab', 'surface pro', 'tab ', 'tablet', 'matebook',
  1571	  'lenovo tab', 'kindle fire',
  1572	  // TV / Monitor
  1573	  'smart tv', 'oled tv', 'qled', 'nanocell', 'frameless tv',
  1574	  'monitor', 'display', '4k tv', '8k tv', 'gaming monitor',
  1575	  // Charger / Power
  1576	  'charger', 'power bank', 'magsafe', 'gan charger', 'wireless charger',
  1577	  // Console / Gaming
  1578	  'playstation', 'xbox', 'nintendo switch', 'steam deck', 'gaming console',
  1579	  // Camera
  1580	  'gopro', 'action cam', 'mirrorless', 'dslr', 'sony a', 'fujifilm',
  1581	  'nikon z', 'canon eos', 'insta360',
  1582	  // Router / Network
  1583	  'router', 'mesh wifi', 'wifi 6', 'wifi 7', 'modem',
  1584	  // Smart Home
  1585	  'echo dot', 'echo show', 'homepod', 'nest hub', 'smart speaker',
  1586	  // E-reader
  1587	  'kindle', 'kobo', 'e-reader', 'ebook reader',
  1588	  // Drone
  1589	  'dji', 'drone', 'quadcopter',
  1590	  // Projector
  1591	  'projector', 'beamer',
  1592	  // Gaming Peripherals
  1593	  'gaming keyboard', 'gaming mouse', 'gaming headset', 'mechanical keyboard',
  1594	  // Robot Vacuum — suction/mapping/battery ndryshojne dukshem mes gjeneratash
  1595	  'roomba', 'roborock', 'ecovacs', 'deebot', 'shark ion', 'shark ai',
  1596	  'eufy robovac', 'dreame', 'robot vacuum',
  1597	  // Massage Gun / Percussion — PPM/bateri/attachments ndryshojne mes modeleve
  1598	  'theragun', 'massage gun', 'hypervolt', 'hyperice',
  1599	  // E-bike / E-scooter — range/top speed/motor ndryshojne dukshem mes viteve
  1600	  'e-bike', 'electric bike', 'electric scooter', 'ninebot', 'segway',
  1601	  'rad power', 'e-scooter',
  1602	  // Portable Power Station — kapaciteti Wh eshte spec-i kryesor, ndryshon 10x
  1603	  'power station', 'jackery', 'ecoflow', 'bluetti', 'anker solix',
  1604	  // Smart Ring — sensoret/bateri ndryshojne mes gjeneratash
  1605	  'oura ring', 'smart ring',
  1606	  // Security Camera / Doorbell — resolution/FOV/bateri ndryshojne mes modeleve
  1607	  'ring doorbell', 'ring camera', 'ring spotlight', 'ring stick up',
  1608	  'arlo pro', 'arlo ultra', 'wyze cam', 'eufy security', 'nest doorbell', 'nest cam',
  1609	  // Connected Fitness Equipment — motor/incline/screen ndryshojne mes tier-ave
  1610	  'peloton', 'nordictrack', 'concept2', 'echelon bike', 'technogym',
  1611	  // 3D Printer — build volume/shpejtesia ndryshojne dukshem mes modeleve
  1612	  '3d printer', 'bambu lab', 'creality', 'prusa',
  1613	  // Portable/Bluetooth Speaker — output W/bateri ndryshojne mes linjave
  1614	  'bluetooth speaker', 'portable speaker', 'jbl flip', 'jbl charge',
  1615	  'jbl xtreme', 'soundlink',
  1616	  // Electric Toothbrush — modes/bateri/presion ndryshojne mes linjave
  1617	  'electric toothbrush', 'oral-b io', 'sonicare',
  1618	  // Air Purifier — CADR/coverage sq ft ndryshojne dukshem mes modeleve
  1619	  'air purifier', 'dyson purifier', 'levoit core',
  1620	];
  1621	
  1622	// Produkte qe kane fjale teknike por NUK kane specs numerike te verifikueshme
  1623	// Keto ANULOHEN nga Tavily sepse do te kthente rezultate te paqarta
  1624	const COMPLEX_TECH_EXCLUSIONS = [
  1625	  'case', 'cover', 'skin', 'sticker', 'sleeve',  // aksesorë pa specs
  1626	  'cable', 'hub', 'dock', 'adapter', 'stand',     // periferi simple
  1627	];
  1628	
  1629	
  1630	function needsTavilySearch(product) {
  1631	  if (!product?.title) return false;
  1632	  const t = product.title.toLowerCase();
  1633	  if (COMPLEX_TECH_EXCLUSIONS.some(k => t.includes(k))) return false;
  1634	  return COMPLEX_TECH_KEYWORDS.some(k => t.includes(k));
  1635	}
  1636	
  1637	// Kerkon specs reale te produktit nepermjet Tavily dhe i kthen si nje
  1638	// vargu specifikash te konfirmuara (te njejtin format si titleSpecs/metafields).
  1639	// Nese Tavily deshtoi (kufiri falas u arrit, API_KEY mungon, timeout),
  1640	// kthehet array bosh — gjenerimi vazhdon normalisht pa specs te konfirmuara.
  1641	async function searchProductSpecs(title) {
  1642	  if (!process.env.TAVILY_API_KEY) return [];
  1643	  try {
  1644	    const res = await axios.post('https://api.tavily.com/search', {
  1645	      api_key: process.env.TAVILY_API_KEY,
  1646	      query: `${title} full specifications IP rating OIS battery mAh`,
  1647	      search_depth: 'basic',
  1648	      max_results: 3,
  1649	      include_answer: false
  1650	    }, { timeout: 4000 });
  1651	
  1652	    const snippets = (res.data.results || [])
  1653	      .map(r => r.content || r.snippet || '')
  1654	      .join('\n')
  1655	      .slice(0, 3000); // kufizoj tokenat qe shkojne ne prompt
  1656	
  1657	    if (!snippets.trim()) return [];
  1658	
  1659	    // Nxjerr specs me regex nga permbajtja e Tavily — i njejti mekanizem
  1660	    // si extractTitleSpecs(), por aplikuar mbi tekst te gjate kerkimi
  1661	    const specs = [];
  1662	    const ram = snippets.match(/(\d+)\s?GB\s*(LPDDR\w*)?\s*RAM/i);
  1663	    if (ram) specs.push({ key: 'RAM', value: `${ram[1]}GB` });
  1664	
  1665	    const storage = snippets.match(/(\d+)\s?(GB|TB)\s*(UFS\w*|NVMe|SSD|storage|internal)/i);
  1666	    if (storage) specs.push({ key: 'Storage', value: `${storage[1]}${storage[2].toUpperCase()}` });
  1667	
  1668	    // Battery — kap "5000mAh", "5,000 mAh", "5.000 mAh"
  1669	    const battery = snippets.match(/(\d[\d,\.]{2,5})\s?mAh/i);
  1670	    if (battery) specs.push({ key: 'Battery', value: `${battery[1].replace(/[,\.]/g, '')}mAh` });
  1671	
  1672	    // Kamera: mer te gjitha MP ne snippets, pastaj merr vlerën me te larte
  1673	    // (kamera kryesore 200MP, jo ultrawide 12MP qe shpesh shfaqet e para)
  1674	    const allMpMatches = [...snippets.matchAll(/(\d+)\s?MP/gi)];
  1675	    if (allMpMatches.length > 0) {
  1676	      const highestMp = allMpMatches.reduce((max, m) => Math.max(max, parseInt(m[1])), 0);
  1677	      if (highestMp > 0) specs.push({ key: 'Main Camera', value: `${highestMp}MP` });
  1678	    }
  1679	
  1680	    const aperture = snippets.match(/f\/(\d+\.?\d*)\s*(aperture|lens|main|wide)/i);
  1681	    if (aperture) specs.push({ key: 'Aperture', value: `f/${aperture[1]}` });
  1682	
  1683	    // Hz — flex: captures 120Hz regardless of what follows
  1684	    const hz = snippets.match(/(\d{2,4})\s?Hz/i);
  1685	    if (hz) specs.push({ key: 'Refresh Rate', value: `${hz[1]}Hz` });
  1686	
  1687	    const charging = snippets.match(/(\d+)\s?W\s*(wired|fast|Super Fast|charging)/i);
  1688	    if (charging) specs.push({ key: 'Charging', value: `${charging[1]}W` });
  1689	
  1690	    const screen = snippets.match(/(\d+\.?\d*)[""\u2033-]\s*(?:inch(?:es?)?|display|screen|AMOLED|OLED|IPS|Liquid)/i)
  1691	                || snippets.match(/(\d+\.?\d*)[- ]inch/i);
  1692	    const screenVal = screen?.[1];
  1693	    if (screenVal && parseFloat(screenVal) > 3) specs.push({ key: 'Screen Size', value: `${screenVal}"` });
  1694	
  1695	    const os = snippets.match(/(iOS|Android|Windows)\s*(\d+)/i);
  1696	    if (os) specs.push({ key: 'OS', value: `${os[1]} ${os[2]}` });
  1697	
  1698	    // Resolution: WQXGA+, 3K, QHD+, 2.8K etj — te laptopet shpesh s'eshte
  1699	    // dimension ne inch por emer standard si "3K WQXGA+" ose "2880x1800"
  1700	    const resName = snippets.match(/\b(WQXGA\+?|QXGA|QHD\+?|FHD\+?|3K|2\.8K|2K|4K|OLED\s*2K)\b/i);
  1701	    if (resName) specs.push({ key: 'Display Resolution', value: resName[1].toUpperCase() });
  1702	
  1703	    // NPU performance: "50 TOPS", "47 TOPS" — metrik AI i reklamuar ne laptop-et 2025-2026
  1704	    const tops = snippets.match(/(\d+)\s?TOPS/i);
  1705	    if (tops) specs.push({ key: 'NPU Performance', value: `${tops[1]} TOPS` });
  1706	
  1707	    // Codename procesori: Panther Lake, Lunar Lake, Arrow Lake, Raptor Lake etj
  1708	    const codename = snippets.match(/\b(Panther Lake|Lunar Lake|Arrow Lake|Raptor Lake|Meteor Lake|Alder Lake|Hawk Point)\b/i);
  1709	    if (codename) specs.push({ key: 'Processor Codename', value: codename[1] });
  1710	
  1711	    // Process node: "Intel 18A", "3nm", "4nm", "TSMC 3nm" etj
  1712	    const processNode = snippets.match(/\b(Intel\s+18A|Intel\s+20A|TSMC\s*\d+nm|\d+nm\s*node|\d+nm\s*process)\b/i);
  1713	    if (processNode) specs.push({ key: 'Process Node', value: processNode[1] });
  1714	
  1715	    // IP rating: IP67, IP68, IP69 — rezistencë ndaj ujit dhe pluhurit
  1716	    const ip = snippets.match(/\b(IP\d{2}[KX]?)\b/i);
  1717	    if (ip) specs.push({ key: 'Water Resistance', value: ip[1].toUpperCase() });
  1718	
  1719	    // OIS — Optical Image Stabilization
  1720	    const ois = snippets.match(/\b(OIS|Optical Image Stabilization)\b/i);
  1721	    if (ois) specs.push({ key: 'OIS', value: 'Yes' });
  1722	
  1723	    // Wireless charging
  1724	    const wireless = snippets.match(/(\d+)\s?W\s*(wireless|Qi|MagSafe|charging)/i);
  1725	    if (wireless) specs.push({ key: 'Wireless Charging', value: `${wireless[1]}W` });
  1726	
  1727	    // Weight
  1728	    const weight = snippets.match(/(\d+)\s?g\s*(weight|weighs|heavy|light)/i);
  1729	    if (weight) specs.push({ key: 'Weight', value: `${weight[1]}g` });
  1730	
  1731	    // Chipset — Exynos, Snapdragon, Dimensity, Tensor, Apple M/A-series (iPhone + Mac)
  1732	    const chipset = snippets.match(/\b(A\d{1,2}\s*(?:Pro|Bionic|Fusion)?|Exynos\s*\d+\w*|Snapdragon\s*[\d\w\s+]+?(?=[\s,\.])|Dimensity\s*\d+\w*|Tensor\s*G?\d+|Apple\s*M\d[\w]*|Helio\s*\w+|Kirin\s*\d+)\b/i);
  1733	    if (chipset) specs.push({ key: 'Chipset', value: chipset[1].trim() });
  1734	
  1735	    // 5G connectivity
  1736	    if (/\b5G\b/i.test(snippets)) specs.push({ key: '5G', value: 'Yes' });
  1737	
  1738	    // WiFi 6/6E/7
  1739	    const wifi = snippets.match(/\b(Wi-Fi\s*[67]E?|WiFi\s*[67])\b/i);
  1740	    if (wifi) specs.push({ key: 'WiFi', value: wifi[1] });
  1741	
  1742	    // Bluetooth version
  1743	    const bt = snippets.match(/Bluetooth\s*(\d+\.?\d*)/i);
  1744	    if (bt) specs.push({ key: 'Bluetooth', value: `Bluetooth ${bt[1]}` });
  1745	
  1746	    console.log(`[tavily] "${title}" — gjeta ${specs.length} spec(e) te konfirmuara`);
  1747	    return specs;
  1748	  } catch (e) {
  1749	    console.warn('[tavily] Kerkimi deshtoi:', e.message);
  1750	    return [];
  1751	  }
  1752	}
  1753	
  1754	// Specifika qe nese gjenden si metafield, konsiderohen "konfirmim i jashtem"
  1755	// per nje produkt tech/electronics — perdoret nga hasExternalConfirmation
  1756	const SPEC_METAFIELD_KEYWORDS = [
  1757	  'battery', 'ram', 'storage', 'display', 'screen', 'camera', 'processor',
  1758	  'cpu', 'chip', 'resolution', 'capacity', 'weight', 'dimension', 'water',
  1759	  'resistance', 'charge', 'watt', 'refresh', 'hz', 'mp', 'gb', 'mah'
  1760	];
  1761	
  1762	function hasSpecMetafields(metafields) {
  1763	  return (metafields || []).some(mf =>
  1764	    SPEC_METAFIELD_KEYWORDS.some(k => (mf.key || '').toLowerCase().includes(k))
  1765	  );
  1766	}
  1767	
  1768	// Zbulon nese titulli ka tashme specifika te konfirmuara nga shitesi (— ose | te ndara)
  1769	// Format: "Nike Pegasus 41 — ReactX | 10mm | 280g" — nese ekziston, AI nuk ka nevoje te shpike
  1770	function hasMerchantSpecsInTitle(title) {
  1771	  if (!title) return false;
  1772	  const afterSeparator = title.split(/[—|]/).slice(1).join(' ');
  1773	  return /\d/.test(afterSeparator);
  1774	}
  1775	
  1776	// "Deri ne" / "up to" — fjala hedge per cdo gjuhe te STEP B; kontrollohet para
  1777	// nje numri specifikash per te zbuluar nese eshte pretendim i "zhveshur" (i
  1778	// rrezikshem) kur s'ka konfirmim te jashtem. Disa gjuhe (NL/PT/PL/SV) s'kane
  1779	// term te perkthyer ne STEP B, pra modeli shpesh mban "up to" anglisht ose
  1780	// perdor termin lokal — i mbulojme te dy rastet me mire-se-asgje.
  1781	const UP_TO_HEDGES = {
  1782	  French: { match: 'jusqu', display: 'jusqu\'à' },
  1783	  German: { match: 'bis zu', display: 'bis zu' },
  1784	  Italian: { match: 'fino a', display: 'fino a' },
  1785	  Spanish: { match: 'hasta', display: 'hasta' },
  1786	  Dutch: { match: 'tot', display: 'tot' },
  1787	  Portuguese: { match: 'até', display: 'até' },
  1788	  Polish: { match: 'do', display: 'do' },
  1789	  Swedish: { match: 'upp till', display: 'upp till' }
  1790	};
  1791	
  1792	// Gjen TE GJITHA rastet e specifikave ne tekst — numer+njesi (mAh, GB/TB, ",
  1793	// Hz, MP, h/ore, W, g, %) OSE aperture kamere (f/1.4, f/1.7). Nje funksion i
  1794	// vetem qe e perdorin te dyja hasUnhedgedSpecNumber dhe forceHedgeSpecNumbers,
  1795	// qe te mos mbahen dy kopje te regex-it ne sinkron dore (aperture u shtua pas
  1796	// rastit real S26 Ultra: "f/1.7" — specifikim i S25 Ultra, jo S26 — qe s'u
  1797	// kap fare nga lista e meparshme e njesive).
  1798	function findSpecMatches(text) {
  1799	  if (!text) return [];
  1800	  const matches = [];
  1801	  const numberUnitPattern = /\d+(?:[.,]\d+)?\s*(mah|gb|tb|"|inch(?:es)?|hz|mp|h\b|hours?|w\b|watts?|g\b|grams?|%|rpm)/gi;
  1802	  const aperturePattern = /f\/\d+(?:\.\d+)?/gi;
  1803	  let m;
  1804	  while ((m = numberUnitPattern.exec(text)) !== null) matches.push({ index: m.index, text: m[0] });
  1805	  while ((m = aperturePattern.exec(text)) !== null) matches.push({ index: m.index, text: m[0] });
  1806	  matches.sort((a, b) => a.index - b.index);
  1807	  return matches;
  1808	}
  1809	
  1810	// Zbulon nje numer specifikash teknike qe NUK eshte i paraprire nga nje fjale
  1811	// "deri ne" brenda ~25 karaktereve para tij. Perdoret VETEM kur
  1812	// hasExternalConfirmation eshte false — nese gjendet numer i "zhveshur",
  1813	// modeli e shkeli gate-in (EXTERNAL CONFIRMATION STATUS ne sharedRules)
  1814	// PAVARESISHT instruksionit ne prompt — shih diskutimin per MacBook Neo:
  1815	// Sonnet 4.6 i bindur nga STEP A "MANDATORY" qe vjen menjehere pas
  1816	// paralajmerimit, ne vend te tij. Kjo eshte rrjeta e sigurise mekanike.
  1817	function hasUnhedgedSpecNumber(text, targetLang) {
  1818	  if (!text) return false;
  1819	  const localHedge = UP_TO_HEDGES[targetLang]?.match;
  1820	  const hedgeWords = ['up to', localHedge].filter(Boolean)
  1821	    .map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  1822	  const hedgeRegex = new RegExp(hedgeWords.join('|'), 'i');
  1823	  return findSpecMatches(text).some(m => {
  1824	    const before = text.slice(Math.max(0, m.index - 25), m.index);
  1825	    return !hedgeRegex.test(before);
  1826	  });
  1827	}
  1828	
  1829	// Zbulon nje emer çipi/procesori me numer brezi konkret (A18, M3 Pro,
  1830	// Snapdragon 8 Elite, Dimensity 9300, Exynos 2400, Tensor G4) — i njejti
  1831	// rrezik konfuzioni si Hz/mAh, por keto jane string emrash jo numer+njesi,
  1832	// pra hasUnhedgedSpecNumber s'i kap. Nese gjendet ndonje, modeli ka shkruar
  1833	// brez specifik pa konfirmim — duhej te shkruante "Apple silicon chip" ose
  1834	// "octa-core processor" pa numrin e brezit, sic e beri sakte rasti iPhone 17 Pro.
  1835	function hasUnconfirmedChipName(text) {
  1836	  if (!text) return false;
  1837	  const chipPattern = /\b(a\d{1,2}\s*(pro|bionic)?\b|m\d\s*(pro|max|ultra)?\b|snapdragon\s*\d+[\w\s+]*|dimensity\s*\d+|exynos\s*\d+|tensor\s*g\d+)/i;
  1838	  return chipPattern.test(text);
  1839	}
  1840	
  1841	// Kontrolli i kombinuar — perdoret nga rrjeta e sigurise me poshte
  1842	function detectGateViolation(text, targetLang) {
  1843	  if (hasUnhedgedSpecNumber(text, targetLang)) return 'unhedged_number';
  1844	  if (hasUnconfirmedChipName(text)) return 'chip_name';
  1845	  return null;
  1846	}
  1847	
  1848	// Shtresa e trete dhe e fundit, DETERMINISTIKE — nuk varet fare nga bindja e
  1849	// modelit. Pas retry-it (suksesshem ose jo), nese ndonje numer specifikash
  1850	// MBETET pa "deri ne", e fut programatikisht para tij. Provuar live: Galaxy
  1851	// S26 Ultra retry e rregulloi emrin e çipit por JO numrat (6.9", 120Hz, 200MP,
  1852	// 5000mAh, 45W mbeten te pa-hedge-uara) — kjo eshte garancia qe i zevendeson
  1853	// shpresat me kontroll mekanik per dimensionin numerik specifikisht. Emrat e
  1854	// çipave NUK trajtohen ketu (s'ka kuptim "up to Snapdragon 8 Gen 4") — ato
  1855	// mbeten vetem ne dore te retry-it. SHENIM: hedge-i e zgjidh besimin e rreme,
  1856	// JO vleren e gabuar nese modeli ka kujtuar specifika te gjeneratres se
  1857	// kaluar (shih rasti aperture f/1.7 vs realja f/1.4) — per kete duhet burim
  1858	// i jashtem, jo vetem riformulim.
  1859	function forceHedgeSpecNumbers(text, targetLang) {
  1860	  if (!text) return text;
  1861	  const hedgeDisplay = UP_TO_HEDGES[targetLang]?.display || 'up to';
  1862	  const localHedge = UP_TO_HEDGES[targetLang]?.match;
  1863	  const hedgeWords = ['up to', localHedge].filter(Boolean)
  1864	    .map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  1865	  const hedgeRegex = new RegExp(hedgeWords.join('|'), 'i');
  1866	
  1867	  const matches = findSpecMatches(text);
  1868	  let result = '';
  1869	  let lastIndex = 0;
  1870	  for (const m of matches) {
  1871	    const before = text.slice(Math.max(0, m.index - 25), m.index);
  1872	    result += text.slice(lastIndex, m.index);
  1873	    if (!hedgeRegex.test(before)) result += `${hedgeDisplay} `;
  1874	    result += m.text;
  1875	    lastIndex = m.index + m.text.length;
  1876	  }
  1877	  result += text.slice(lastIndex);
  1878	  return result;
  1879	}
  1880	
  1881	// Regjistron shkeljen ne Supabase per matje reale (jo vetem console.log) —
  1882	// kerkon tabelen 'gate_violations' (shih SQL e dhene ne pergjigje). Nese
  1883	// tabela mungon, dështon ne heshtje me warning, s'e nderpret gjenerimin.
  1884	async function logGateViolation(shop, product, targetLang, violationType, retryFixed) {
  1885	  try {
  1886	    await supabase.from('gate_violations').insert({
  1887	      shop: shop || 'test',
  1888	      product_id: String(product?.id || ''),
  1889	      product_title: product?.title || '',
  1890	      target_lang: targetLang,
  1891	      violation_type: violationType,
  1892	      retry_fixed: retryFixed
  1893	    });
  1894	  } catch (e) {
  1895	    console.warn('[gate-violation] Logging ne Supabase deshtoi (tabela mungon?):', e.message);
  1896	  }
  1897	}
  1898	
  1899	// Ngjyrat e njohura — listuara nga me e gjata te me e shkurtra qe te mos
  1900	// kapet pjeserisht (p.sh. "space gray" para "gray")
  1901	const COLOR_KEYWORDS = [
  1902	  'rose gold', 'space gray', 'space grey', 'midnight blue', 'desert titanium',
  1903	  'black', 'white', 'silver', 'gold', 'blue', 'red', 'green', 'pink',
  1904	  'purple', 'gray', 'grey', 'titanium', 'graphite', 'midnight', 'starlight',
  1905	  'natural', 'desert', 'sage', 'lavender', 'teal', 'orange', 'yellow',
  1906	  'bronze', 'copper'
  1907	].sort((a, b) => b.length - a.length);
  1908	
  1909	// Nxjerr specifika DIREKT nga titulli me regex — keto behen "konfirmim i
  1910	// jashtem" pikerisht si metafields, sepse AI s'i merr nga kujtesa, i lexon
  1911	// thjesht nga teksti. Eliminon halucinimin per keto lloje (jo e zvogelon —
  1912	// e eliminon, sepse s'i kerkohet fare modelit te "kujtohet" per to).
  1913	function extractTitleSpecs(title) {
  1914	  if (!title) return [];
  1915	  const specs = [];
  1916	
  1917	  // RAM gjendet fillimisht, qe storage te dije cilin "XXXGB" te perjashtoje
  1918	  const ramRegexMatch = title.match(/(\d+)\s?GB\s*RAM\b/i) || title.match(/RAM\s*(\d+)\s?GB\b/i);
  1919	  if (ramRegexMatch) specs.push({ key: 'RAM', value: `${ramRegexMatch[1]}GB` });
  1920	
  1921	  // Storage: gjej TE GJITHA rastet GB/TB ne titull, perjashto pozicionin e
  1922	  // RAM-it (jo vleren numerike — dy fusha te ndryshme mund te kene rastesisht
  1923	  // te njejtin numer), merr te paren e mbetur
  1924	  const ramSpan = ramRegexMatch ? [ramRegexMatch.index, ramRegexMatch.index + ramRegexMatch[0].length] : null;
  1925	  const sizeMatches = [...title.matchAll(/(\d+)\s?(GB|TB)\b/gi)];
  1926	  const storageHit = sizeMatches.find(m => !ramSpan || m.index < ramSpan[0] || m.index >= ramSpan[1]);
  1927	  if (storageHit) specs.push({ key: 'Storage', value: `${storageHit[1]}${storageHit[2].toUpperCase()}` });
  1928	
  1929	  const batteryMatch = title.match(/(\d+)\s?mAh\b/i);
  1930	  if (batteryMatch) specs.push({ key: 'Battery', value: `${batteryMatch[1]}mAh` });
  1931	
  1932	  const cameraMatch = title.match(/(\d+)\s?MP\b/i);
  1933	  if (cameraMatch) specs.push({ key: 'Camera', value: `${cameraMatch[1]}MP` });
  1934	
  1935	  const hzMatch = title.match(/(\d+)\s?Hz\b/i);
  1936	  if (hzMatch) specs.push({ key: 'Refresh Rate', value: `${hzMatch[1]}Hz` });
  1937	
  1938	  const wattMatch = title.match(/(\d+)\s?W\b(?!h)/i); // perjashto "Wh"
  1939	  if (wattMatch) specs.push({ key: 'Power', value: `${wattMatch[1]}W` });
  1940	
  1941	  const tLower = title.toLowerCase();
  1942	  const colorHit = COLOR_KEYWORDS.find(c => tLower.includes(c));
  1943	  if (colorHit) specs.push({ key: 'Color', value: colorHit.replace(/\b\w/g, c => c.toUpperCase()) });
  1944	
  1945	  return specs;
  1946	}
  1947	
  1948	// Vetem specifikat numerike (jo ngjyra) konsiderohen mjaftueshem per te
  1949	// aktivizuar hasExternalConfirmation — ngjyra s'eshte vete burim halucinimi
  1950	// hardware, eshte thjesht detaj per ta perfshire saktë ne pershkrim.
  1951	function hasVolatileTitleSpec(titleSpecs) {
  1952	  return titleSpecs.some(s => s.key !== 'Color');
  1953	}
  1954	
  1955	// Generic fallback
  1956	function isGenericProduct(product) { return true; }
  1957	
  1958	// Sport & Fitness keywords
  1959	const SPORT_FITNESS_TYPES = [
  1960	  'sport', 'fitness', 'gym', 'workout', 'training', 'recovery', 'yoga', 'running', 'cycling'
  1961	];
  1962	const SPORT_FITNESS_TITLE_KEYWORDS = [
  1963	  'theragun', 'massage gun', 'foam roller', 'percussion', 'therabody',
  1964	  'hyperice', 'hypervolt', 'achedaway',
  1965	  'dumbbell', 'barbell', 'kettlebell', 'resistance band', 'pull-up bar',
  1966	  'yoga mat', 'jump rope', 'battle rope', 'rowing machine', 'treadmill',
  1967	  'stationary bike', 'peloton', 'concept2', 'bowflex',
  1968	  'whoop', 'oura ring', 'sports watch',
  1969	  'whey protein', 'creatine', 'pre-workout', 'bcaa', 'protein bar',
  1970	  'energy gel', 'electrolyte', 'sports nutrition',
  1971	  'compression sleeve', 'swim goggle', 'swim cap', 'wetsuit'
  1972	];
  1973	function isSportFitnessProduct(product) {
  1974	  const type = (product.product_type || '').toLowerCase();
  1975	  const title = (product.title || '').toLowerCase();
  1976	  if (SPORT_FITNESS_TYPES.some(t => type.includes(t))) return true;
  1977	  return SPORT_FITNESS_TITLE_KEYWORDS.some(k => title.includes(k));
  1978	}
  1979	
  1980	// Fashion & Apparel keywords
  1981	const FASHION_APPAREL_TYPES = [
  1982	  'clothing', 'apparel', 'fashion', 'shoes', 'footwear', 'accessories',
  1983	  'bags', 'jewelry', 'watches', 'sportswear', 'activewear', 'outerwear'
  1984	];
  1985	const FASHION_APPAREL_TITLE_KEYWORDS = [
  1986	  // Shoes
  1987	  'sneaker', 'shoe', 'boot', 'sandal', 'loafer', 'trainer', 'running',
  1988	  'air max', 'ultraboost', 'stan smith', 'chuck taylor', 'vans', 'converse',
  1989	  // Clothing
  1990	  't-shirt', 'tshirt', 'shirt', 'hoodie', 'jacket', 'coat', 'dress',
  1991	  'jeans', 'pants', 'trousers', 'shorts', 'leggings', 'sweater', 'cardigan',
  1992	  'blazer', 'suit', 'skirt', 'blouse', 'polo', 'vest', 'parka', 'anorak',
  1993	  // Accessories
  1994	  'bag', 'handbag', 'backpack', 'wallet', 'belt', 'scarf', 'hat', 'cap',
  1995	  'watch', 'sunglasses', 'jewelry', 'bracelet', 'necklace', 'ring',
  1996	  // Brands
  1997	  'nike', 'adidas', 'puma', 'reebok', 'new balance', 'under armour',
  1998	  'levi', 'zara', 'h&m', 'uniqlo', 'ralph lauren', 'tommy hilfiger',
  1999	  'north face', 'columbia', 'patagonia', 'arc teryx', 'parka', 'anorak', 'windbreaker', 'tracksuit', 'sweatshirt', 'overcoat'
  2000	];
  2001	
  2002	function isFashionApparelProduct(product) {
  2003	  const type = (product.product_type || '').toLowerCase();
  2004	  const title = (product.title || '').toLowerCase();
  2005	  if (FASHION_APPAREL_TYPES.some(t => type.includes(t))) return true;
  2006	  return FASHION_APPAREL_TITLE_KEYWORDS.some(k => title.includes(k));
  2007	}
  2008	
  2009	// Home & Kitchen keywords — per detektim nga titulli kur product_type mungon
  2010	const HOME_KITCHEN_TYPES = [
  2011	  'kitchen', 'home', 'cooking', 'baking', 'appliance', 'cookware'
  2012	];
  2013	const HOME_KITCHEN_TITLE_KEYWORDS = [
  2014	  'mixer', 'blender', 'coffee', 'espresso', 'nespresso', 'french press',
  2015	  'kettle', 'toaster', 'air fryer', 'instant pot', 'knife', 'knives',
  2016	  'pan', 'pot', 'wok', 'skillet', 'cookware', 'bakeware', 'stand mixer',
  2017	  'food processor', 'juicer', 'grinder', 'rice cooker', 'slow cooker',
  2018	  'waffle', 'crepe', 'vacuum', 'dyson', 'kitchenaid', 'delonghi',
  2019	  'nespresso', 'tefal', 'bosch', 'siemens', 'braun'
  2020	];
  2021	
  2022	function isHomeKitchenProduct(product) {
  2023	  const type = (product.product_type || '').toLowerCase();
  2024	  const title = (product.title || '').toLowerCase();
  2025	  if (HOME_KITCHEN_TYPES.some(t => type.includes(t))) return true;
  2026	  return HOME_KITCHEN_TITLE_KEYWORDS.some(k => title.includes(k));
  2027	}
  2028	
  2029	async function generateProductCopy(product, targetLang, glossary, cleanBody, imageUrl, metafields = [], shop = null) {
  2030	
  2031	  // KILL SWITCH GLOBAL — vendos GENERATION_PAUSED=true te Vercel Environment
  2032	  // Variables per te ndaluar ÇDO gjenerim menjëherë, pavarësisht rrugës.
  2033	  if (process.env.GENERATION_PAUSED === 'true') {
  2034	    throw new Error('PLAN_LIMIT: Generation is paused. Set GENERATION_PAUSED=false in Vercel to resume.');
  2035	  }
  2036	  const category = product.product_type || '';
  2037	  const tags = (product.tags || '').split(',').slice(0, 5).join(', ');
  2038	  const hasImage = !!imageUrl;
  2039	  const homeKitchen = isHomeKitchenProduct(product);
  2040	  const beautyHealth = !homeKitchen && isBeautyHealthProduct(product);
  2041	  const sportFitness = !homeKitchen && !beautyHealth && isSportFitnessProduct(product);
  2042	  const fashionApparel = !homeKitchen && !beautyHealth && !sportFitness && isFashionApparelProduct(product);
  2043	  const techElectronics = !homeKitchen && !beautyHealth && !sportFitness && !fashionApparel && isTechElectronicsProduct(product);
  2044	  const isGeneric = !homeKitchen && !beautyHealth && !sportFitness && !fashionApparel && !techElectronics;
  2045	
  2046	  // Konfirmim i jashtem: titulli ka specifika te shitesit (— ose |), OSE
  2047	  // titulli ka specifika te nxjerra direkt me regex (GB/TB/mAh/MP/Hz/W/RAM),
  2048	  // OSE metafields kane te dhena specifikash reale. Nese asnje nuk eshte e
  2049	  // vertete, STEP A (recall nga memoria) çaktivizohet me poshte ne sharedRules
  2050	  // per specifika VOLATILE — shih EXTERNAL CONFIRMATION STATUS.
  2051	  const titleSpecs = extractTitleSpecs(product.title);
  2052	  let hasExternalConfirmation = hasMerchantSpecsInTitle(product.title) ||
  2053	    hasSpecMetafields(metafields) || hasVolatileTitleSpec(titleSpecs);
  2054	
  2055	  // ─── TAVILY WEB SEARCH (para cdo gjeje tjeter) ────────────────────────────
  2056	  // Tavily kerkohet PARA se te ndertohet prompt-i i Sonnet — ky eshte qellimi:
  2057	  // Sonnet merr te dhena REALE nga web, jo nga kujtesa e trajnimit. Sekuenca
  2058	  // eshte e garantuar nga "await": searchProductSpecs() bllokon ekzekutimin
  2059	  // deri sa Tavily pergjigjet (max 8s), vetem pastaj ndertohet confirmedSpecsBlock,
  2060	  // vetem pastaj ndertohet userContent, vetem pastaj thirret Sonnet.
  2061	  //
  2062	  // KUSHTI I TREFISHTË — te gjitha duhet te jene te verteta:
  2063	  // 1. !hasExternalConfirmation — tashmë kemi specs (titulli/metafields): Tavily ANASHKALOHET
  2064	  //    (do te shpenzojme 0.1 cent per te gjetur dicka qe e kemi)
  2065	  // 2. !cleanBody — produkti ka tashme pershkrim (perkthim): Tavily ANASHKALOHET
  2066	  //    (cleanBody = pershkrim ekzistues → route direkt te Gemini perkthim, jo gjenerim)
  2067	  // 3. needsTavilySearch(product) — vetem telefona/laptop/PC: Tavily ANASHKALOHET
  2068	  //    per te gjitha grupet e tjera (fashion, supplements, earbuds, watches etj)
  2069	  //    qe kane dale mire ne testime pa kete shtrese shtese kostoje
  2070	  let tavilySpecs = [];
  2071	  let tavilySearchedButEmpty = false;
  2072	  if (!hasExternalConfirmation && !cleanBody && needsTavilySearch(product)) {
  2073	    console.log(`[tavily] Duke kerkuar specs per "${product.title}" — Sonnet pret...`);
  2074	    tavilySpecs = await searchProductSpecs(product.title);
  2075	    if (tavilySpecs.length > 0) {
  2076	      hasExternalConfirmation = true;
  2077	      console.log(`[tavily] ${tavilySpecs.length} spec(e): ${tavilySpecs.map(s => `${s.key}=${s.value}`).join(', ')}`);
  2078	    } else {
  2079	      // NO-SPECS mode vetem per produkte pa brand te njohur —
  2080	      // iPhone, Samsung etj. kane specs te besueshme ne training data te Sonnet
  2081	      // dhe duhet te shkruaje me hedging "up to", jo zero specs
  2082	      if (!titleHasKnownBrand(product.title)) {
  2083	        tavilySearchedButEmpty = true;
  2084	        console.log(`[tavily] Asnje spec + brand i panjohur → NO-SPECS mode`);
  2085	      } else {
  2086	        console.log(`[tavily] Asnje spec nga Tavily por brand i njohur → hedged specs nga Sonnet`);
  2087	      }
  2088	    }
  2089	  }
  2090	  // ──────────────────────────────────────────────────────────────────────────
  2091	
  2092	  const allConfirmedSpecs = [
  2093	    ...titleSpecs,
  2094	    ...tavilySpecs,
  2095	    ...metafields.slice(0, 15).map(mf => ({ key: mf.key, value: mf.value }))
  2096	  ];
  2097	  const confirmedSpecsBlock = allConfirmedSpecs.length > 0
  2098	    ? `\nPRODUCT SPECS (verified data — use these values directly without hedging):\n${allConfirmedSpecs.map(s => `- ${s.key}: ${s.value}`).join('\n')}\n`
  2099	    : '';
  2100	
  2101	  console.log(`[category] homeKitchen:${homeKitchen} beautyHealth:${beautyHealth} sportFitness:${sportFitness} fashionApparel:${fashionApparel} techElectronics:${techElectronics} externalConfirmation:${hasExternalConfirmation} product:"${product.title}"`);
  2102	
  2103	  // ─── LANGUAGE CONFIG ───────────────────────────────────────────────────────
  2104	  // Rregulla specifike per cdo gjuhe: tone, CTA, sensory words, forbidden words
  2105	  const LANG_CONFIG = {
  2106	    French: {
  2107	      tone: 'vous',
  2108	      cta: 'Commandez maintenant',
  2109	      sensoryWords: 'arômes, rituel, plaisir, saveur, élégance, douceur, art, savoir-faire',
  2110	      avoidWords: 'performances, efficacité, fonctionnalité, robuste, solide, durable',
  2111	      avoidNote: 'Never repeat "durable", "robuste", "solide" more than once — replace with "conçue pour durer", "de qualité", "artisanale"',
  2112	      bulletOrder: '1) Specs (capacity/size/weight) → 2) Mechanism (how it works) → 3) Design/emotion (style, origin, feel) → 4) Care/warranty (dishwasher, guarantee)'
  2113	    },
  2114	    German: {
  2115	      tone: 'Sie',
  2116	      cta: 'Jetzt kaufen',
  2117	      sensoryWords: 'Genuss, Wärme, Aroma, Qualität, Handwerk, Präzision, Erlebnis',
  2118	      avoidWords: 'robust, solide, hochwertig, effizient, funktional, langlebig, strapazierfähig',
  2119	      avoidNote: 'Avoid "robust", "hochwertig", "langlebig" — use "gefertigt für den Alltag", "verarbeitet", "von hoher Qualität" instead',
  2120	      bulletOrder: '1) Specs (Fassungsvermögen/Maße) → 2) Funktion (wie es arbeitet) → 3) Design/Emotion (Stil, Herkunft) → 4) Pflege/Garantie'
  2121	    },
  2122	    Italian: {
  2123	      tone: 'Lei',
  2124	      cta: 'Acquista ora',
  2125	      sensoryWords: 'aroma, calore, piacere, sapore, eleganza, artigianalità, raffinatezza',
  2126	      avoidWords: 'robusto, solido, durevole, efficiente, funzionale, performance',
  2127	      avoidNote: 'Avoid repeating "robusto" or "durevole" — use "di qualità", "realizzato per durare", "artigianale"',
  2128	      bulletOrder: '1) Specifiche (capacità/dimensioni) → 2) Meccanismo (come funziona) → 3) Design/Emozione → 4) Cura/Garanzia'
  2129	    },
  2130	    Spanish: {
  2131	      tone: 'usted',
  2132	      cta: 'Compra ahora',
  2133	      sensoryWords: 'aroma, calidez, ritual, placer, sabor, elegancia, artesanal',
  2134	      avoidWords: 'robusto, sólido, duradero, eficiente, funcional, rendimiento',
  2135	      avoidNote: 'Avoid repeating "robusto" or "duradero" — use "de calidad", "diseñado para durar", "artesanal"',
  2136	      bulletOrder: '1) Especificaciones (capacidad/tamaño) → 2) Mecanismo (cómo funciona) → 3) Diseño/Emoción → 4) Cuidado/Garantía'
  2137	    },
  2138	    Dutch: {
  2139	      tone: 'u',
  2140	      cta: null,
  2141	      sensoryWords: 'aroma, warmte, genot, smaak, kwaliteit, vakmanschap',
  2142	      avoidWords: 'robuust, solide, duurzaam, efficiënt, functioneel',
  2143	      avoidNote: 'Avoid repeating "robuust" or "duurzaam" — use "kwalitatief", "gemaakt om lang mee te gaan"',
  2144	      bulletOrder: '1) Specificaties → 2) Werking → 3) Design/Gevoel → 4) Onderhoud/Garantie'
  2145	    },
  2146	    Portuguese: {
  2147	      tone: 'você',
  2148	      cta: null,
  2149	      sensoryWords: 'aroma, calor, ritual, prazer, sabor, elegância, artesanal',
  2150	      avoidWords: 'robusto, sólido, durável, eficiente, funcional',
  2151	      avoidNote: 'Avoid repeating "robusto" or "durável" — use "de qualidade", "feito para durar", "artesanal"',
  2152	      bulletOrder: '1) Especificações → 2) Mecanismo → 3) Design/Emoção → 4) Cuidados/Garantia'
  2153	    },
  2154	    Polish: {
  2155	      tone: 'Pan/Pani',
  2156	      cta: null,
  2157	      sensoryWords: 'aromat, ciepło, przyjemność, smak, elegancja, rzemiosło',
  2158	      avoidWords: 'solidny, trwały, wydajny, funkcjonalny',
  2159	      avoidNote: 'Avoid repeating "solidny" or "trwały" — use "wysokiej jakości", "wykonany z dbałością"',
  2160	      bulletOrder: '1) Specyfikacje → 2) Mechanizm → 3) Design/Emocja → 4) Pielęgnacja/Gwarancja'
  2161	    },
  2162	    Swedish: {
  2163	      tone: 'du',
  2164	      cta: null,
  2165	      sensoryWords: 'arom, värme, njutning, smak, kvalitet, hantverk',
  2166	      avoidWords: 'robust, solid, hållbar, effektiv, funktionell',
  2167	      avoidNote: 'Avoid repeating "robust" or "hållbar" — use "kvalitativ", "tillverkad för att hålla"',
  2168	      bulletOrder: '1) Specifikationer → 2) Funktion → 3) Design/Känsla → 4) Skötsel/Garanti'
  2169	    },
  2170	    Danish: {
  2171	      tone: 'du',
  2172	      cta: null,
  2173	      sensoryWords: 'aroma, varme, nydelse, smag, kvalitet, håndværk',
  2174	      avoidWords: 'robust, solid, holdbar, effektiv, funktionel',
  2175	      avoidNote: 'Avoid repeating "robust" or "holdbar" — use "kvalitetsrig", "lavet til at holde"',
  2176	      bulletOrder: '1) Specifikationer → 2) Funktion → 3) Design/Følelse → 4) Pleje/Garanti'
  2177	    },
  2178	    Norwegian: {
  2179	      tone: 'du',
  2180	      cta: null,
  2181	      sensoryWords: 'aroma, varme, nytelse, smak, kvalitet, håndverk',
  2182	      avoidWords: 'robust, solid, holdbar, effektiv, funksjonell',
  2183	      avoidNote: 'Avoid repeating "robust" or "holdbar" — use "kvalitetsrik", "laget for å vare"',
  2184	      bulletOrder: '1) Spesifikasjoner → 2) Funksjon → 3) Design/Følelse → 4) Vedlikehold/Garanti'
  2185	    },
  2186	    Czech: {
  2187	      tone: 'Vy',
  2188	      cta: null,
  2189	      sensoryWords: 'vůně, teplo, potěšení, chuť, kvalita, řemeslo',
  2190	      avoidWords: 'robustní, solidní, trvanlivý, efektivní, funkční',
  2191	      avoidNote: 'Avoid repeating "robustní" or "trvanlivý" — use "kvalitní", "vyrobeno pro dlouhou životnost"',
  2192	      bulletOrder: '1) Specifikace → 2) Funkce → 3) Design/Emoce → 4) Péče/Záruka'
  2193	    },
  2194	    Romanian: {
  2195	      tone: 'dumneavoastră',
  2196	      cta: null,
  2197	      sensoryWords: 'aromă, căldură, plăcere, gust, calitate, meșteșug',
  2198	      avoidWords: 'robust, solid, durabil, eficient, funcțional',
  2199	      avoidNote: 'Avoid repeating "robust" or "durabil" — use "de calitate", "conceput pentru a dura"',
  2200	      bulletOrder: '1) Specificații → 2) Mecanism → 3) Design/Emoție → 4) Îngrijire/Garanție'
  2201	    },
  2202	    Hungarian: {
  2203	      tone: 'Ön',
  2204	      cta: null,
  2205	      sensoryWords: 'illat, meleg, öröm, íz, minőség, kézművesség',
  2206	      avoidWords: 'robusztus, szilárd, tartós, hatékony, funkcionális',
  2207	      avoidNote: 'Avoid repeating "robusztus" or "tartós" — use "minőségi", "hosszú élettartamra tervezve"',
  2208	      bulletOrder: '1) Specifikációk → 2) Funkció → 3) Design/Érzelem → 4) Karbantartás/Garancia'
  2209	    },
  2210	    Arabic: {
  2211	      tone: 'أنت',
  2212	      cta: 'اشترِ الآن',
  2213	      sensoryWords: 'عطر، دفء، متعة، جودة، حرفية',
  2214	      avoidWords: 'متين، صلب، دائم، فعّال، عملي',
  2215	      avoidNote: 'Use rich descriptive language. Keep numbers and specs in Western numerals.',
  2216	      bulletOrder: '1) المواصفات (السعة/الحجم) → 2) الآلية (كيف يعمل) → 3) التصميم/الشعور → 4) الرعاية/الضمان'
  2217	    },
  2218	    Japanese: {
  2219	      tone: 'です・ます',
  2220	      cta: '今すぐ購入',
  2221	      sensoryWords: '香り、温かさ、品質、職人技、精緻さ',
  2222	      avoidWords: '丈夫、頑丈、耐久性、効率的、機能的',
  2223	      avoidNote: 'Use polite です・ます form. Emphasize craftsmanship and quality over technical specs.',
  2224	      bulletOrder: '1) 仕様（容量/サイズ） → 2) 機能（どのように働くか） → 3) デザイン/感覚 → 4) お手入れ/保証'
  2225	    },
  2226	    Korean: {
  2227	      tone: '합쇼체',
  2228	      cta: '지금 구매하기',
  2229	      sensoryWords: '향기, 따뜻함, 품질, 장인정신, 정밀함',
  2230	      avoidWords: '견고한, 내구성, 효율적, 기능적',
  2231	      avoidNote: 'Use formal 합쇼체 form. Emphasize quality and design.',
  2232	      bulletOrder: '1) 사양 (용량/크기) → 2) 기능 (작동 방식) → 3) 디자인/감성 → 4) 관리/보증'
  2233	    },
  2234	    Turkish: {
  2235	      tone: 'siz',
  2236	      cta: 'Şimdi satın al',
  2237	      sensoryWords: 'aroma, sıcaklık, keyif, kalite, ustalık',
  2238	      avoidWords: 'sağlam, dayanıklı, verimli, işlevsel',
  2239	      avoidNote: 'Avoid repeating "sağlam" or "dayanıklı" — use "kaliteli", "uzun ömürlü tasarlanmış"',
  2240	      bulletOrder: '1) Özellikler → 2) İşlev → 3) Tasarım/Duygu → 4) Bakım/Garanti'
  2241	    },
  2242	    Indonesian: {
  2243	      tone: 'Anda',
  2244	      cta: 'Beli sekarang',
  2245	      sensoryWords: 'aroma, kehangatan, kenikmatan, kualitas, keahlian',
  2246	      avoidWords: 'kokoh, solid, tahan lama, efisien, fungsional',
  2247	      avoidNote: 'Avoid repeating "kokoh" or "tahan lama" — use "berkualitas", "dirancang untuk bertahan"',
  2248	      bulletOrder: '1) Spesifikasi → 2) Fungsi → 3) Desain/Perasaan → 4) Perawatan/Garansi'
  2249	    },
  2250	    'Brazilian Portuguese': {
  2251	      tone: 'você',
  2252	      cta: 'Compre agora',
  2253	      sensoryWords: 'aroma, calor, prazer, sabor, qualidade, artesanal',
  2254	      avoidWords: 'robusto, sólido, durável, eficiente, funcional',
  2255	      avoidNote: 'Use Brazilian Portuguese expressions, not European. Avoid "durável" — use "feito para durar"',
  2256	      bulletOrder: '1) Especificações → 2) Mecanismo → 3) Design/Emoção → 4) Cuidados/Garantia'
  2257	    },
  2258	    English: {
  2259	      tone: 'you',
  2260	      cta: null,
  2261	      sensoryWords: 'precision, clarity, craftsmanship, quality, performance',
  2262	      avoidWords: 'cutting-edge, stunning, sleek, vibrant, reliable, dependable, practical, seamless, next-level, game-changing, powerful, robust, immersive, advanced, innovative, revolutionary, exceptional, ultimate, premium, superior, effortless, intelligent',
  2263	      avoidNote: 'Replace marketing adjectives with the real spec — use exact chip name, screen size, MP count instead of vague words like reliable, vibrant, powerful',
  2264	      bulletOrder: '1) Processor/Chipset + core count → 2) Screen size inches + Hz + display tech → 3) Camera MP + aperture + OIS if confirmed → 4) Battery mAh + charge W + IP rating if confirmed (e.g. IP67/IP68) + 5G if confirmed'
  2265	    }
  2266	  };
  2267	
  2268	  const langCfg = LANG_CONFIG[targetLang] || {
  2269	    tone: 'you',
  2270	    cta: null,
  2271	    sensoryWords: 'quality, warmth, craftsmanship, pleasure, elegance',
  2272	    avoidWords: 'robust, solid, durable, efficient, functional, performance',
  2273	    avoidNote: 'Avoid repeating the same adjective more than once',
  2274	    bulletOrder: '1) Specs (capacity/size) → 2) Mechanism (how it works) → 3) Design/Emotion → 4) Care/Warranty'
  2275	  };
  2276	
  2277	  // Nderto content array per API (tekst + imazh kur eshte Sonnet)
  2278	  let userContent;
  2279	
  2280	  // Blloku i rregullave te perbashketa per te dy promptet
  2281	  const sharedRules = `
  2282	TITLE RULES:
  2283	- CRITICAL: NEVER modify, extend, or add specs to the original product name. Translate it naturally but keep it identical in structure.
  2284	  WRONG: "iPhone 15 Pro" → "iPhone 15 Pro — A17 Pro | 6.1" | 48MP" (added specs — FORBIDDEN)
  2285	  RIGHT: "iPhone 15 Pro" → "iPhone 15 Pro" (identical, only translated if non-English name)
  2286	- Only add specs if the merchant ALREADY included them in the title (e.g. "Nike Pegasus 41 — ReactX | 10mm")
  2287	- No ALL CAPS, no exclamation marks
  2288	- Max 70 chars
  2289	
  2290	UNIT CONVERSION — apply automatically for all non-English languages:
  2291	When specs contain imperial units, convert to metric for FR/DE/IT/ES/NL/PT/PL/SV:
  2292	- sq in → cm² (× 6.45), sq ft → m² (× 0.093), oz fluid → ml (× 29.6)
  2293	- oz weight → g (× 28.3), lbs → kg (× 0.453), °F → °C ((F-32)×5/9)
  2294	- BTU → kW (× 0.000293), miles → km (× 1.609), inches → cm (× 2.54)
  2295	Format: metric first, imperial in parentheses. French: comma decimal "4,5 kg"
  2296	NEVER write "po²", "sq in", "lbs", "°F" alone in FR/DE/IT/ES outputs.
  2297	
  2298	MERCHANT SPEC OVERRIDE — HIGHEST PRIORITY:
  2299	If the product title contains specs separated by | or — (e.g. "Nike Pegasus 41 — ReactX | 10mm | 280g | Daily Trainer"):
  2300	- Extract ALL specs from the title: foam type, drop, weight, use case, ATM, battery, etc.
  2301	- Use these specs DIRECTLY in the bullets — they are merchant-confirmed, never override them
  2302	- Do NOT invent additional specs beyond what is in the title
  2303	- Format recognition: anything after — or between | characters = confirmed spec
  2304	- Examples:
  2305	  "Garmin Fenix 8 Solar — MIP | 10 ATM | 48j Smartwatch" → use MIP (not AMOLED), 10 ATM, 48j smartwatch mode
  2306	  "Theragun Pro Plus — 16mm | 60lbs | 1.2kg" → use exactly these numbers, do not add others
  2307	  "Oura Ring Gen 4 — Titane | 4-5j | 10 ATM" → use titanium, 4-5 days (not 7), 10 ATM
  2308	This rule overrides Step A, Step B, and all category knowledge — merchant specs are ground truth.
  2309	
  2310	DESCRIPTION RULES:
  2311	- Opening sentence: always start with what the customer GETS or FEELS, not what the product IS.
  2312	  WRONG: "Yogurt is a fermented dairy product..." RIGHT: "Smooth and creamy — ideal for breakfast, cooking, or a quick snack."
  2313	- Write 1-2 opening sentences MAX — SHORT and grounded. Lead with the product's KEY DIFFERENTIATOR (main confirmed spec, target use, or brand promise). Never write "The large screen provides..." or vague statements — always anchor to a real spec or concrete benefit. Examples of GOOD intros: "Run all-day on a single charge." / "48MP precision in every shot." / "The A18 Pro chip handles what others can't."
  2314	- The intro should state an OUTCOME the spec produces, not restate the spec's name. When two specs work together, combine them into one outcome sentence instead of just naming the strongest one.
  2315	  WRONG (restates spec name): "The i9-14900HX puts serious processing headroom under every session."
  2316	  RIGHT (states outcome): "240Hz visuals stay locked in even when the RTX 4080 is pushed to its limit."
  2317	- PREFERRED PATTERN when the product serves two distinct use-cases (e.g. gaming + creative work, everyday + travel, professional + casual): use both allowed sentences as one connected pair, not two separate thoughts.
  2318	  Sentence 1: name the two use-cases this product serves — short, general framing, no spec yet.
  2319	  Sentence 2: name the product, then connect 2 real confirmed specs directly to the 2 outcomes named in sentence 1.
  2320	  Example: "Built for gaming and creative work that demands full performance. The Legion Pro 7i pairs a 24-core i9-14900HX with an RTX 4080 — enough headroom for competitive frame rates or 4K video exports without slowdown."
  2321	  Both specs named in the intro (i9-14900HX, RTX 4080 in this example) must also appear in their own bullets below — the intro previews, the bullets confirm with full detail. Never name a spec in the intro that isn't backed by a bullet.
  2322	  NEVER add unverified superlatives to make this pattern work: no "fastest", "best-in-class", "professional-grade" unless that exact phrase is a confirmed spec, not a comparison.
  2323	- Sensory/emotional words are allowed ONLY if they add real meaning. FORBIDDEN: "Découvrez", "Explorez", "Entdecken Sie", "nuage", "honore", "incontournable", "rituel", "magie", "transforme" — these are empty metaphors.
  2324	- Preferred words for ${targetLang}: ${langCfg.sensoryWords}
  2325	- AVOID: ${langCfg.avoidWords}
  2326	- ${langCfg.avoidNote}
  2327	- Address the customer using "${langCfg.tone}"
  2328	- Then write exactly 4 bullet points starting with •, each on its own line separated by a SINGLE \n (not double \n\n), in this order:
  2329	  ${langCfg.bulletOrder}
  2330	- The intro sentence and first bullet are separated by a SINGLE \n — NO blank line between them
  2331	- Format: "Intro sentence.\n• Bullet 1\n• Bullet 2\n• Bullet 3\n• Bullet 4"
  2332	- ONE spec per bullet — NEVER combine multiple specs in one bullet.
  2333	  WRONG: "• Écran 6,9", 120Hz, 200MP, 5000mAh" (4 specs in 1 bullet — FORBIDDEN)
  2334	  RIGHT: "• Écran 6,9" Dynamic AMOLED 2X — 120Hz\\n• [next spec]\\n• [next spec]\\n• [next spec]"
  2335	- Each bullet MUST start with • and be separated from the next by \\n (newline character)
  2336	- Each bullet MUST contain a number, measurement, or confirmed technical fact. Poetry bullets are FORBIDDEN.
  2337	  EXCEPTION for unknown/generic products (Step C): if no number is confirmed, write the most specific functional or sensory fact available — never invent a number.
  2338	- RATIO: 80% technical facts, 20% tone. Not the reverse.
  2339	- SPEC-TO-BENEFIT RULE: every bullet must contain a real spec (never remove this), but state WHY it matters to the buyer, not just WHAT it is. This is not about adding vague adjectives — it's about connecting the number to a concrete outcome the customer experiences.
  2340	  WRONG (dry spec sheet): "Intel Core i9-14900HX — 24-core architecture for sustained workloads"
  2341	  RIGHT (spec + outcome): "Intel Core i9-14900HX — 24 cores keep frame rates steady through heavy multitasking"
  2342	  WRONG: "16" QHD display — 240Hz refresh rate for fluid, frame-accurate visuals" (restates the spec twice, no outcome)
  2343	  RIGHT: "16" QHD display — 240Hz keeps fast-paced action sharp, zero motion blur"
  2344	  The spec is never sacrificed for tone — both must be present in every bullet.
  2345	- Total description max 120 words
  2346	
  2347	CATEGORY KNOWLEDGE RULE:
  2348	
  2349	EXTERNAL CONFIRMATION STATUS: ${hasExternalConfirmation ? 'CONFIRMED — see CONFIRMED MERCHANT DATA below or merchant title for real spec data.' : 'NOT CONFIRMED — no merchant-provided specs exist for this product.'}
  2350	${tavilySearchedButEmpty ? `
  2351	⛔ NO-SPECS MODE ACTIVE: An external search was performed for this product but returned ZERO verified specifications. This means the product either does not exist yet, is too new, or its specs are unverifiable. In this case you MUST:
  2352	- Write ZERO numeric specifications (no RAM, no storage, no battery mAh, no screen size in inches, no camera MP, no Hz, no watts, no weight)
  2353	- Write ZERO chip/processor model names or generation numbers
  2354	- Write ZERO OS version numbers
  2355	- Write ONLY marketing-focused copy: design language, intended use case, target audience, brand positioning, what problem it solves
  2356	- DO NOT use "up to" hedging — simply omit all specs entirely
  2357	- If you cannot write a meaningful description without specs, write about the brand's reputation, the product category's benefits, and the experience of using this type of product
  2358	This rule overrides STEP A, STEP B, and STEP C entirely.` : (!hasExternalConfirmation ? `Because there is no external confirmation, STEP A's permission to write an exact number from memory is SUSPENDED for VOLATILE specs (RAM, storage, battery mAh, screen Hz, camera MP, screen size, chip generation number, or any measurement that differs between similar models and is easy to confuse) — use "up to" / qualitative framing for these instead, even if you recognize the brand and model with high confidence. This suspension does NOT apply to STABLE IDENTIFIERS tied to release timing rather than hardware configuration — the current OS version (e.g. "iOS 26", "Android 16") or a platform feature/brand name (e.g. "Apple Intelligence", "Galaxy AI") may be stated directly if you are confident, since these carry far lower cross-model confusion risk than hardware measurements. If unsure about a stable identifier too, omit it rather than guess.` : '')}
  2359	
  2360	You are an ecommerce expert with deep product knowledge across all categories. Apply this logic:
  2361	
  2362	STEP A — KNOWN BRAND + MODEL (MANDATORY SPECS):
  2363	If you recognize the exact product (Samsung Galaxy S25 Ultra, iPhone 16 Pro Max, Sony WF-1000XM6, Apple AirPods Pro, Dyson V15, Nespresso Vertuo, Nike Air Max 270, etc.):
  2364	
  2365	MANDATORY:
  2366	→ At least 3 bullets must contain a specific confirmed number or spec name.
  2367	→ Generic phrases are STRICTLY FORBIDDEN — these are marketing words, not specs: "advanced processor", "powerful chip", "high resolution", "long battery life", "imagerie IA avancée", "traitement avancé", "exigeantes et créatives", "tâches complexes", "performances optimisées", "s'adapte à votre", "s'ajuste à votre", "compiti impegnativi", "intelligent features", "stunning display", "incredible camera", "next-generation", "optimisées pour", "précision intentionnelle", "double action", "à double action", "formule innovante", "technologie avancée", "soin intensif". If you catch yourself writing any of these, replace with the real ingredient, number, or spec name.
  2368	→ Write the REAL name: "Snapdragon 8 Elite" not "advanced chip". "A18 Pro 3nm" not "powerful processor".
  2369	→ ONE spec per bullet — never combine. WRONG: "• A18 Pro gère les tâches exigeantes et créatives". RIGHT: "• Puce A18 Pro 3nm — Neural Engine 16 cœurs".
  2370	→ If you know 2 numbers for the same spec (e.g. battery + charge speed), they count as ONE bullet: "• 5000mAh — charge 45W filaire en 70 min".
  2371	→ UNCERTAINTY RULE — CRITICAL: If you are not 100% certain of a specific number (chip generation, exact MP count, exact mAh, number of sensors/motors/cyclones), do NOT invent it. Instead use "up to" framing, describe it qualitatively ("multiple sensors", "advanced sensor array"), or omit the uncertain number. WRONG: "• Puce A19 Pro" (A19 doesn't exist) or "• 8 pressure sensors" (invented count). RIGHT: "• Puce A17 Pro 3nm" (confirmed) or "• Piezo sensor adjusts suction automatically" (no fake count). If unsure whether it's A17 or A18, write "Puce Apple Pro 3nm" without the generation number. A fabricated spec is worse than a missing one — merchants will publish it as fact.
  2372	→ PROCESSOR NAME RULE: If you recognize the brand but are NOT certain of the exact processor name for this specific model (e.g. Samsung Galaxy A55, mid-range phones, older flagships) → write "octa-core processor" or omit entirely. NEVER invent a chip name. WRONG: "MediaTek Dimensity 6000" (invented). RIGHT: "Processeur octa-core" or skip bullet and use confirmed spec instead.
  2373	
  2374	Priority specs by product type — use these exact data points:
  2375	- Smartphone → 1) processor name + nm node  2) screen: inches + Hz + tech  3) main camera MP + aperture  4) battery mAh + charge W
  2376	- Earbuds → 1) ANC dB level  2) battery h per bud + case h  3) Bluetooth version + codec  4) driver size mm or charge time
  2377	- Laptop/tablet → 1) processor + cores  2) RAM GB + storage TB/GB  3) screen inches + resolution  4) battery hours
  2378	- Smartwatch → 1) battery days  2) sensors: HR + SpO2 + ECG if available  3) water resistance ATM  4) GPS type
  2379	- Camera → 1) sensor MP + size  2) aperture f/  3) zoom range  4) video max resolution + fps
  2380	- Vacuum/appliance → 1) suction power W or Pa  2) capacity L or dust bin  3) runtime min  4) filtration HEPA or not
  2381	- Skincare → 1) active ingredient + %  2) skin type target  3) clinically tested claim  4) texture/finish
  2382	- Supplement → 1) mg per dose  2) key active ingredient  3) servings per container  4) certification (vegan, GMP)
  2383	- Knife/cookware → 1) steel grade  2) hardness HRC  3) blade length cm  4) handle material
  2384	- Over-ear headphones → 1) ANC processor name (e.g. QN1, ACAA)  2) battery hours confirmed (e.g. WH-1000XM5=30h, XM4=30h)  3) Bluetooth version + codec (LDAC, aptX, AAC)  4) weight g + foldable yes/no
  2385	  CRITICAL for Sony WH-1000XM5: 30h battery, QN1 processor, BT 5.2, LDAC, 250g, foldable. NEVER write 8h.
  2386	  CRITICAL for Bose QC45: 24h battery, BT 5.1, AAC/SBC, 238g.
  2387	  CRITICAL for Sony WH-1000XM4: 30h battery, QN1 processor, BT 5.0, LDAC, 254g.
  2388	- Running shoe → 1) midsole foam type  2) drop mm  3) weight g  4) outsole rubber type
  2389	
  2390	STEP B — KNOWN CATEGORY, UNKNOWN BRAND:
  2391	If you recognize the category but NOT the specific model:
  2392	→ Use "up to" / "jusqu'à" / "bis zu" / "fino a" / "hasta" for all numbers — signals typical range, not exact.
  2393	→ Use realistic mid-to-premium values.
  2394	
  2395	Category typical ranges (use "up to" framing):
  2396	- Earbuds → up to 8h + 30h case, ANC up to 35dB, BT 5.3, charge in 2h
  2397	- Smartphone → up to 6.7" AMOLED 120Hz, up to 108MP, up to 5000mAh, up to 67W charge
  2398	- Smartwatch → up to 7-day battery, HR + SpO2, 5ATM, GPS, up to 2h charge
  2399	- Laptop → up to 16GB RAM, up to 1TB SSD, up to 15h battery, up to 2K display
  2400	- Coffee maker → brew in 4 min, up to 1L, 60min heat retention, stainless filter
  2401	- French press → up to 1L, stainless plunger, heat-safe borosilicate glass
  2402	- Fitness/resistance → up to 40kg resistance, 6 muscle groups, latex-free option
  2403	- Supplement → typical dose per serving, GMP certified, key active ingredient
  2404	- Knife/cookware → 420-grade steel, up to 58 HRC, up to 20cm blade
  2405	- Phone charger → up to 65W, USB-C, up to 1.5m braided cable
  2406	- Power bank → up to 20000mAh, up to 22.5W, up to 2 ports
  2407	- Running shoe → EVA midsole, breathable mesh upper, rubber outsole, drop 8-10mm
  2408	- Skincare/serum → active concentration, skin type, visible results 4-6 weeks
  2409	
  2410	STEP C — UNKNOWN CATEGORY:
  2411	Does not match any known category → write ONLY what is confirmed from the name or image.
  2412	CRITICAL: Describe what the CUSTOMER experiences (taste, texture, feel, use-case, benefit) — NOT how the product is made or manufactured, unless the process itself is a marketed differentiator (e.g. "cold-pressed", "stone-ground", "slow-fermented 48h").
  2413	WRONG: "Yogurt is a fermented dairy product made with live bacterial cultures" (Wikipedia/process)
  2414	RIGHT: "Creamy texture, tangy flavour — versatile for breakfast, cooking, or as a snack" (customer experience)
  2415	If the title gives NO specs (brand, type, size, %) → keep description SHORT (2 sentences max + 4 bullets), honest, and grounded in what IS confirmed. Never invent brand, weight, fat%, origin, or specific culture names.
  2416	
  2417	RULE: "up to" = typical range (Step B). Real confirmed numbers = Step A only. Never mix.
  2418	
  2419	${fashionApparel ? `
  2420	FASHION & APPAREL SPECIFIC RULES:
  2421	This is a clothing, footwear, or accessory product. Apply these rules:
  2422	
  2423	PRIORITY SPECS by product type:
  2424	
  2425	FOOTWEAR (sneakers, running shoes, boots):
  2426	- Bullet 1: sole technology + material (e.g. "Semelle React + unité Air Max 270° — amorti réactif")
  2427	- Bullet 2: upper material + construction (e.g. "Empeigne mesh respirant + renforts synthétiques")
  2428	- Bullet 3: fit + sizing info (e.g. "Pointure fidèle — convient pour usage lifestyle quotidien")
  2429	- Bullet 4: care instructions (e.g. "Nettoyage à la main recommandé — semelle caoutchouc durable")
  2430	- ALWAYS mention: sole type, upper material, occasion (running/lifestyle/training)
  2431	- IF KNOWN: weight (g), drop (mm), "true to size" or "size up"
  2432	
  2433	CLOTHING (t-shirts, hoodies, jackets, dresses):
  2434	- Bullet 1: fabric composition % (e.g. "100% coton biologique — doux et respirant")
  2435	- Bullet 2: fit type + cut (e.g. "Coupe regular — taille fidèle, longueur standard")
  2436	- Bullet 3: key feature or design (e.g. "Poche kangourou — cordon de serrage ajustable")
  2437	- Bullet 4: care instructions (e.g. "Lavage machine 30°C — ne pas sécher au sèche-linge")
  2438	- ALWAYS mention: material %, fit type, wash care
  2439	
  2440	BAGS & ACCESSORIES — MANDATORY, this is not optional guidance:
  2441	If capacity (liters) or dimensions are known for this product, they MUST appear somewhere in the 4 bullets — a bag description that omits a known capacity number is a failed response, rewrite before responding.
  2442	- Bullet 1: material + dimensions if known (e.g. "Cuir grainé — 30×20×10cm, 0,8kg")
  2443	- Bullet 2: capacity + compartments (e.g. "15L — compartiment principal + 2 poches zippées")
  2444	- Bullet 3: closure + strap type (e.g. "Fermeture éclair YKK — bandoulière réglable incluse")
  2445	- Bullet 4: care + warranty
  2446	
  2447	FORBIDDEN for Fashion & Apparel:
  2448	- "intemporel", "authentique", "iconique" alone — always follow with a concrete spec: WRONG: "coupe intemporelle" / RIGHT: "coupe droite depuis 1873"
  2449	- "style intemporel" without describing the actual style
  2450	- "confort optimal" — write the material or technology that creates comfort
  2451	- "coloris polyvalents" alone — always add the actual colorway name if known
  2452	- "traverse les générations", "savoir-faire légendaire" — empty heritage claims without facts
  2453	- Never write "taille fidèle" without confirming it — write "vérifier le guide des tailles" if unsure
  2454	
  2455	FIT LANGUAGE — always use precise fit terms, never vague descriptions:
  2456	- RIGHT: "Coupe Regular — taille naturelle, jambe droite" / "Slim fit — taille mi-haute, effilé à la cheville"
  2457	- WRONG: "silhouette épurée", "coupe flatteuse", "style moderne"
  2458	- For jeans specifically: always mention waist rise (taille naturelle/mi-haute/basse) + leg cut (droit/slim/bootcut) + fabric composition if known (e.g. "100% coton", "denim rigide non-stretch") — for well-known models like Levi's 501, this material is a confirmed stable fact, not a guess
  2459	
  2460	TONE: aspirational but grounded — mix lifestyle language with concrete specs.
  2461	` : ''}
  2462	
  2463	${sportFitness ? `
  2464	SPORT & FITNESS SPECIFIC RULES:
  2465	This is a sport, fitness, or recovery product.
  2466	
  2467	GENERAL RULES:
  2468	- NEVER write "portatif" unless weight is confirmed < 0.8 kg
  2469	- NEVER combine "athlètes sérieux" with "bien-être" — choose ONE audience
  2470	- ALWAYS mention the key differentiator vs cheaper models in the same line
  2471	
  2472	VARIANT UNCERTAINTY RULE — CRITICAL:
  2473	When the product name contains a variant identifier (Solar, AMOLED, Pro, Plus, Ultra, Max, Elite, SE):
  2474	- These identifiers change specs fundamentally between variants
  2475	- VERIFY before writing: does this variant have this spec?
  2476	- Specs that DIFFER by variant → write "selon version" or use "up to" framing
  2477	- Specs UNIVERSAL to all variants → write as confirmed
  2478	- NEVER mix specs from different variants of the same product line
  2479	- Examples of dangerous mix-ups:
  2480	  Garmin Fenix 8 Solar = MIP display / Fenix 8 AMOLED = AMOLED display — MUTUALLY EXCLUSIVE
  2481	  Theragun Pro Plus = 2 batteries / Theragun Pro = 1 battery — different models
  2482	  Apple Watch Ultra = 10 ATM / Apple Watch SE = 50m — different resistance
  2483	- RULE: if you know the variant suffix but are not 100% certain of that variant's spec → write "up to" or omit
  2484	
  2485	WATER RESISTANCE — verify before writing, always specify real-world limitations:
  2486	- 5 ATM = rain, splashes, hand washing only — NOT swimming
  2487	- 10 ATM = pool swimming, snorkeling, calm water — NOT diving or high-velocity water sports
  2488	- 20 ATM+ = scuba diving
  2489	- Never write 5 ATM for a product confirmed at 10 ATM (undersells), and never write "sports aquatiques"/"water sports" for 10 ATM without the diving/high-velocity limitation
  2490	
  2491	DISPLAY TYPE — verify before writing:
  2492	- Solar models typically use MIP/transflective (better in sunlight, lower power)
  2493	- AMOLED models use AMOLED (vivid colors, higher power draw)
  2494	- Never write AMOLED for a Solar variant — they are physically incompatible
  2495	
  2496	BATTERY LIFE — always specify the mode, use realistic ranges (not maximum theoretical):
  2497	- Format: "48 jours smartwatch / 145h GPS / 550 jours expedition (avec solaire)" or "4-5 jours (jusqu'à 7 jours mode économie)"
  2498	- Never write "X jours" or "jusqu'à X jours" alone — always specify the mode and use a realistic range, not the max
  2499	
  2500	MASSAGE GUN / PERCUSSION THERAPY (Theragun, Hyperice, Hypervolt, Achedaway):
  2501	- Bullet 1: PPM + amplitude mm confirmed for this exact model
  2502	- Bullet 2: batteries × autonomy = total hours (e.g. "2 batteries × 150 min = 5h total")
  2503	- Bullet 3: PRO differentiators — OLED forcemètre, Bluetooth app, guided routines if Pro/Plus
  2504	- Bullet 4: attachments count + weight kg
  2505	- FORBIDDEN: "portatif" for Theragun Pro, Pro Plus, Elite (all >0.8 kg)
  2506	- FORBIDDEN: "bien-être" for Pro/Elite models — write "usage professionnel et récupération athlétique"
  2507	
  2508	FITNESS EQUIPMENT (dumbbells, kettlebells, resistance bands):
  2509	- Bullet 1: weight/resistance range + increments
  2510	- Bullet 2: material + grip type
  2511	- Bullet 3: muscle groups targeted
  2512	- Bullet 4: dimensions + storage
  2513	
  2514	PROFESSIONAL GYM EQUIPMENT (Concept2, Rogue, Eleiko, Technogym, Life Fitness):
  2515	- Bullet 1: resistance mechanism + technology name (e.g. "Volant d'inertie air — résistance auto-régulée")
  2516	- Bullet 2: monitor/screen name + connectivity (e.g. "Performance Monitor PM5 — Bluetooth/ANT+, WiFi, Zwift")
  2517	- Bullet 3: capacity + adjustability (e.g. "Capacité 227kg — course ajustable 38-48" pour 140-210cm")
  2518	- Bullet 4: storage + warranty (e.g. "Démontable 2 parties <30 sec — garantie 5 ans cadre, 2 ans pièces")
  2519	- ALWAYS mention: exact component names (PM5, J-cups, etc.), max capacity, warranty terms
  2520	- SOCIAL PROOF: if used at CrossFit Games, Olympics, or pro clubs — mention it: "utilisé aux CrossFit Games et clubs professionnels"
  2521	- NEVER write "professionnel" without proof — write the actual proof instead
  2522	- REBRANDING: if product was renamed, mention: "Anciennement [Old Name] — même mécanisme, rebrand [year]"
  2523	- COMPATIBLE APPS: always list if known (Zwift, Garmin Connect, Polar, ErgData, Concept2 Logbook)
  2524	
  2525	CONNECTED FITNESS BIKES & CARDIO (Peloton, NordicTrack, Ergatta, iFit, Echelon):
  2526	- Bullet 1: KEY DIFFERENTIATOR vs base model (e.g. "Auto-Follow — résistance auto-ajustée selon le cours")
  2527	- Bullet 2: screen size + rotation + class types (e.g. "Écran tactile rotatif 23,8" — classes live et on-demand")
  2528	- Bullet 3: connectivity + ecosystem (e.g. "Apple GymKit, WiFi, Bluetooth 5.0 — compatible Apple Watch instantané")
  2529	- Bullet 4: warranty PER COMPONENT — never write single warranty:
  2530	  Format: "X ans cadre, Y mois pièces, Z mois main-d'œuvre"
  2531	  Peloton Bike+: 5 ans cadre, 12 mois pièces/électronique, 12 mois main-d'œuvre
  2532	  Never write "12 mois" alone for Peloton — undersells vs NordicTrack 10 ans
  2533	- ALWAYS mention: pedal system (Look Delta, SPD, toe cages) + if shoes included or sold separately
  2534	- ALWAYS mention: key differentiator that justifies premium over base model
  2535	- SUBSCRIPTION: never write specific price — "Abonnement requis — voir tarifs sur peloton.com"
  2536	- INCOMPATIBILITIES: if not compatible with Zwift or other apps → mention "non compatible apps tierces"
  2537	
  2538	SPORTS WEARABLES (Garmin, Polar, Whoop, Oura):
  2539	- Bullet 1: battery life with mode specified (smartwatch / GPS / expedition)
  2540	- Bullet 2: display type CONFIRMED for this variant + resolution
  2541	- Bullet 3: key sensors (HR, SpO2, HRV) + differentiating features (TOPO maps, ClimbPro, PacePro)
  2542	- Bullet 4: water resistance ATM CONFIRMED + weight g
  2543	
  2544	SPORTS NUTRITION:
  2545	- Bullet 1: key active + g per serving
  2546	- Bullet 2: servings per container + flavor
  2547	- Bullet 3: additional blend
  2548	- Bullet 4: certification if confirmed
  2549	
  2550	SUBSCRIPTION & BUSINESS MODEL TRANSPARENCY:
  2551	If the product requires a subscription (Whoop, Peloton, Oura, etc.):
  2552	- MANDATORY: mention subscription requirement — never hide it
  2553	- NEVER write a specific price for subscriptions — prices change and vary by region
  2554	- Format: "Abonnement requis — voir tarifs sur [brand].com" or "Abonnement mensuel ou annuel requis"
  2555	- If device is free with subscription → mention: "Appareil inclus avec abonnement"
  2556	- French buyers hate surprise pricing — transparency without wrong numbers builds trust
  2557	
  2558	SCREENLESS DEVICES:
  2559	If the product has no screen (Whoop, Oura Ring, smart rings):
  2560	- Frame "no screen" as a BENEFIT: "Aucun écran — conception minimaliste, autonomie maximale"
  2561	- Explain where data is accessed: "Toutes vos données sur l'app [brand] (iOS/Android)"
  2562	- Never write "synchronise" when data only exists in the app — write "affichage exclusif sur app"
  2563	
  2564	SENSOR ACCURACY — never write "24/7" without verifying each sensor individually:
  2565	- HR (fréquence cardiaque) → typically continuous 24/7 — write "surveillance continue FC"
  2566	- HRV → typically continuous or nightly — verify before writing "continue"
  2567	- SpO2 → most wearables = nocturne + spot check ONLY — NEVER write "SpO2 continue" unless confirmed
  2568	- Température cutanée → typically continuous — write "surveillance continue température"
  2569	- Format: "Surveillance continue : FC, HRV, température. SpO2 nocturne et spot check."
  2570	
  2571	WEARABLE MATERIALS & SIZING:
  2572	- If titanium confirmed → always mention: "Titane — [weight]g, légèreté et résistance"
  2573	- If sizing kit required (Oura Ring) → always mention: "Kit d'essayage gratuit disponible avant commande"
  2574	- Material differentiates premium from budget — never omit confirmed material
  2575	
  2576	TONE: performance-driven, factual, direct — no poetry, no vague lifestyle claims.
  2577	
  2578	PROSE OPENING RULES — MANDATORY for Sport & Fitness:
  2579	NEVER start with: "Découvrez", "Explorez", "Plongez", "vers les sommets", "élégance de l'aventure"
  2580	ALWAYS start with: KEY DIFFERENTIATOR + ONE SPEC.
  2581	Example: "Montre GPS multisport avec écran MIP — autonomie 21 jours smartwatch."
  2582	` : ''}
  2583	
  2584	${isGeneric ? `
  2585	GENERIC & UNKNOWN PRODUCT RULES — ZERO HALLUCINATION:
  2586	Write ONLY what is confirmed in the title or image. Never invent specs.
  2587	
  2588	LEGO SETS: piece count + set name, mechanism, age recommendation, dimensions
  2589	CANDLES: weight + burn time, fragrance notes, wax type, vessel format
  2590	STATIONERY: format + pages, ruling type, cover + closure, extras
  2591	HANDMADE: mention "fait main" only if confirmed, never invent materials
  2592	FOOD & GROCERY — OVERRIDE bulletOrder: ignore the general bullet order above. Use ONLY this food-specific order:
  2593	- Bullet 1: texture + taste (e.g. "• Texture crémeuse — saveur naturellement acidulée")
  2594	- Bullet 2: use-case + occasions (e.g. "• Petit-déjeuner, smoothies, sauces, marinades")
  2595	- Bullet 3: versatility or serving suggestion — ONLY confirmed facts, NO invented attributes.
  2596	  If nothing is confirmed → write "• Nature ou aromatisé — à déguster seul ou avec des fruits"
  2597	  NEVER write "Sans additifs artificiels" unless confirmed in the title or product info.
  2598	- Bullet 4: storage/serving (e.g. "• À conserver au réfrigérateur — consommer frais")
  2599	FORBIDDEN for food: "fermentation", "bactéries", "cultures", "probiotiques", "digestibilité", "additifs artificiels" — unless explicitly stated in the title.
  2600	If title = "Yogurt" only → write customer experience (taste/texture/use-case) only. Do NOT invent Danone, Greek, 0%, Bifidus, brand, or origin.
  2601	If title includes brand or type (e.g. "Fage Total 0% Greek Yogurt 500g") → use those confirmed specs directly.
  2602	
  2603	TONE: honest, simple, informative — no poetry, no invented features.
  2604	` : ''}
  2605	
  2606	${homeKitchen ? `
  2607	HOME & KITCHEN SPECIFIC RULES:
  2608	This is a kitchen/home appliance product. Apply these additional rules:
  2609	
  2610	TONE RATIO OVERRIDE — for this category ONLY, replace the general "80% facts, 20% tone" rule with:
  2611	45% specs + 35% emotion + 20% lifestyle moment. Specs are never dropped or invented — every bullet still needs a real number — but the surrounding language should feel warm and tied to a real moment in someone's day (morning coffee, weekend baking, family dinner), not read like a spec sheet.
  2612	  WRONG (too clinical for this category): "The Vertuo Pop uses Centrifusion at 7,000 RPM to read each capsule and extract the right result every time."
  2613	  RIGHT (same facts, warmer, moment-based): "The Vertuo Pop turns your morning ritual into something worth savoring — from a quick espresso before the school run to a full mug you actually sit down with."
  2614	Apply the same moment-based framing inside bullets too — connect the spec to when/how someone actually uses it, not just what it does.
  2615	
  2616	- PRIORITY SPECS: motor power (W), capacity (L or ml), speed settings (number), included accessories
  2617	- If brand+model is known (KitchenAid 5KSM175PS, Dyson V15, Nespresso Vertuo): list ALL confirmed specs — W, L, speeds, accessories
  2618	- Bullet 1: capacity + material (e.g. "Bol inox 4,8 L — compatible lave-vaisselle")
  2619	- Bullet 2: motor/mechanism with W and speed (e.g. "Moteur 300W — 10 vitesses, mélange planétaire")
  2620	- Bullet 3: accessories included (e.g. "Fouet, batteur plat et crochet pétrin inclus")
  2621	- Bullet 4: care + warranty confirmed facts only
  2622	- PROSE: use "plaisir", "savoir-faire", "art", "précision" — NEVER "chaleur" for appliances (chaleur = physical heat, wrong context)
  2623	- Do NOT use "chaleur" for mixers, blenders, or any appliance that does not produce heat
  2624	
  2625	CLOSED ECOSYSTEM RULE — applies to ALL products with proprietary consumables or subscriptions:
  2626	Products: Nespresso, Keurig, Dolce Gusto, Peloton, NordicTrack, Apple, Philips Hue, Ring, etc.
  2627	
  2628	MANDATORY for closed ecosystem products:
  2629	1. SPECIFY the ecosystem in title and description — never write generic "capsules" or "subscription":
  2630	   - Nespresso Vertuo → "Capsules Nespresso Vertuo exclusives" (NOT "capsules Nespresso")
  2631	   - Nespresso Original → "Capsules Nespresso Original" (NOT "capsules Nespresso")
  2632	   - These two systems are INCOMPATIBLE — never write "capsules Nespresso" without specifying the line
  2633	2. SPECIFY incompatibilities explicitly — this prevents returns and negative reviews:
  2634	   - "Capsules Vertuo exclusives — non compatibles avec capsules Original Line"
  2635	   - "Abonnement requis — non compatible avec Zwift ou apps tierces"
  2636	3. SPECIFY all formats the machine supports — never limit to one:
  2637	   - Nespresso Vertuo Pop → NOT "machine à espresso" → "machine multi-formats : espresso (40ml) à mug (230ml)"
  2638	   - Keurig → "compatible K-Cup pods uniquement"
  2639	4. USE correct technical terms:
  2640	   - Nespresso crema → "crema" (Italian technical term) NOT "crème riche"
  2641	   - Centrifusion → always mention the RPM if known (7 000 tr/min)
  2642	` : ''}
  2643	
  2644	${beautyHealth ? `
  2645	BEAUTY & HEALTH SPECIFIC RULES:
  2646	This is a skincare, beauty, or supplement product. Max description length: 150 words.
  2647	
  2648	PRIORITY — write these first if confirmed:
  2649	1. Brand technology name (MVE Technology, Vitamin C stable form, Retinol 0.1%)
  2650	2. Key active ingredients with % if known (3 Ceramides essentiels, Acide hyaluronique, Niacinamide 10%)
  2651	3. Skin type target (peaux sensibles, peaux grasses, tous types de peau)
  2652	4. Dermatologist / clinically tested claim if true for this brand
  2653	5. Format value — never "plusieurs semaines": use "jusqu'à 3 mois" for 473ml+, "jusqu'à 6 semaines" for smaller
  2654	
  2655	BULLET ORDER for Beauty & Health:
  2656	- Bullet 1: format + usage duration (e.g. "Flacon 473ml — jusqu'à 3 mois d'utilisation quotidienne")
  2657	- Bullet 2: key active ingredients + technology (e.g. "3 Céramides essentiels + Technologie MVE — hydratation 24h")
  2658	- Bullet 3: skin type + dermatologist claim (e.g. "Testé dermatologiquement — peaux sensibles et normales")
  2659	- Bullet 4: texture/format + confirmed care (e.g. "Formule sans parfum, non-comédogène — sans rinçage")
  2660	
  2661	STRICTLY FORBIDDEN for Beauty & Health:
  2662	- "aucune condition de stockage spéciale" — never mention storage unless required
  2663	- "plusieurs semaines" — always use specific duration
  2664	- "revitalisé", "apaisé" without a confirmed active ingredient backing it
  2665	- "précision intentionnelle", "double action", "formule innovante" — AI nonsense, never use
  2666	- Generic claims without ingredient: "hydrate deeply" → write "Acide hyaluronique — hydratation en profondeur"
  2667	
  2668	FOR ACTIVE SERUMS (niacinamide, retinol, acids, peptides, vitamin C):
  2669	- Write pH if known for the brand (The Ordinary Niacinamide: pH 5.5-7.0)
  2670	- Write confirmed free-from claims: "sans parfum, sans alcool, sans silicone" if true for this brand
  2671	- Write chemical compatibility if known: "Compatible avec Retinol et Peptides — éviter avec Vitamine C pure"
  2672	- Use clinical tone — The Ordinary brand language is transparent, ingredient-focused, no marketing fluff
  2673	- For The Ordinary specifically: always mention "Développé sans parfum, sans alcool, sans silicone"
  2674	- NEVER use "précision intentionnelle", "double action", "à double action" — these are meaningless
  2675	
  2676	FOR EAU THERMALE PRODUCTS (Avène, Vichy, Uriage, La Roche-Posay Thermal Water):
  2677	- ALWAYS mention silica/oligo-éléments content if known (Avène: 36mg/L silice — anti-irritante)
  2678	- ALWAYS mention "sans conservateur, sans parfum" if confirmed
  2679	- ADD secondary uses if confirmed: fixateur de maquillage, après-soleil, soulage piqûres d'insectes
  2680	- ADD "adapté aux bébés et femmes enceintes" if confirmed for the brand
  2681	- NEVER use metaphors: "nuage", "honore", "source magique" — use clinical descriptors instead
  2682	- Tone: pure, transparent, scientific — not poetic
  2683	
  2684	FOR ALL DERMATOLOGICAL & PHARMACEUTICAL BRANDS (La Roche-Posay, Avène, Bioderma, Eucerin, Vichy, Neutrogena, CeraVe, Uriage, Nuxe, A-Derma, Caudalie, and any brand positioned as dermatologist-tested or pharmacy brand):
  2685	
  2686	MANDATORY rules — apply to every product from these brands:
  2687	1. HERO INGREDIENT — always mention the brand's signature asset if known:
  2688	   - La Roche-Posay → "Eau Thermale de La Roche-Posay" (in every product)
  2689	   - Avène → "Eau Thermale d'Avène"
  2690	   - Uriage → "Eau Thermale d'Uriage"
  2691	   - CeraVe → "3 Céramides essentiels + Technologie MVE"
  2692	   - Other brands → identify their hero ingredient from your knowledge
  2693	2. PATENTED TECHNOLOGY — mention if known:
  2694	   - LRP sunscreen → "Mexoryl SX + XL" or "UVMune 400"
  2695	   - CeraVe → "Technologie MVE — libération sur 24h"
  2696	   - Other brands → use confirmed technology name only
  2697	3. PRACTICAL INFO by product type:
  2698	   - SPF/sunscreen → "photostable", "résistant à l'eau", "réappliquer toutes les 2h"
  2699	   - Moisturizer → "hydratation 24h" or "48h" if confirmed
  2700	   - Cleanser → "sans savon", "pH physiologique" if confirmed
  2701	   - Eye cream → "zone contour des yeux testée ophtalmologiquement" if confirmed
  2702	4. TONE — always clinical and trustworthy, NEVER glamour or aspirational:
  2703	   - RIGHT: "Spécialement formulé pour peaux sensibles et réactives"
  2704	   - WRONG: "Découvrez l'élégance d'un soin qui transforme votre peau"
  2705	5. NEVER use "formule avancée" for dermatological brands — always replace with the real technology name
  2706	6. SKIN TYPE — always specify: "peaux sensibles", "peaux grasses", "peaux sèches à très sèches", "tous types de peau"
  2707	
  2708	BRAND HERITAGE & AUTHORITY — if the brand has a founding claim, invention, or official positioning, mention it in prose or bullet:
  2709	- Bioderma → "Inventeur de la micellaire depuis 1995" / "Inventore della micellare dal 1995"
  2710	- La Roche-Posay → "N°1 en dermatologie recommandée par les dermatologues"
  2711	- CeraVe → "Développé avec des dermatologues"
  2712	- Avène → "Source thermale depuis 1736"
  2713	- Vichy → "Recommandé par les professionnels de santé"
  2714	- Eucerin → "Plus de 100 ans d'expertise dermatologique"
  2715	- Neutrogena → "Recommandé par les dermatologues"
  2716	- Other brands → use ONLY confirmed official claims — never invent a heritage claim
  2717	
  2718	PRIORITY SPECS for micellar water / eau micellaire:
  2719	- pH value if known (Bioderma Sensibio: pH 5.5)
  2720	- "sans rinçage" — mandatory if confirmed
  2721	- Makeup removal scope: "removes waterproof makeup" if confirmed
  2722	- Duration from format: 500ml → "jusqu'à 6 semaines", 250ml → "jusqu'à 3 semaines"
  2723	` : ''}
  2724	
  2725	META TITLE RULES (max 60 chars):
  2726	- Format: "[Product Name] [key spec]" — ALWAYS include one key spec, never just the product name alone
  2727	- Key spec examples: "with 5000mAh Battery", "48MP Camera", "A18 Pro Chip", "120Hz Display", "IP68"
  2728	- Main keyword first, spec second
  2729	- No punctuation at the end
  2730	- WRONG: "iPhone 16 Pro Max" (no spec) — RIGHT: "iPhone 16 Pro Max with A18 Pro Chip"
  2731	- MANDATORY: if the product name does not already state its own type (serum, cream, shampoo, shoe, mixer, jeans, backpack, etc.), include that type word in ${targetLang} as part of the spec — this must stay CONSISTENT across every language. A meta_title that includes the type word in one language but drops it in another (in favor of a benefit phrase) is a failed response — check every language's meta_title against every other before responding.
  2732	  WRONG (EN has it, FR drops it): EN "...Zinc 1% Serum" / FR "...Zinc 1% pour le teint" (lost "Sérum")
  2733	  RIGHT: FR "...Zinc 1% Sérum" — same type word kept, benefit phrase can still appear in the meta_description instead
  2734	  WRONG (EN has it, FR drops it): EN "Levi's 501 Original Straight Leg Jeans" / FR "Levi's 501 Original avec coupe droite" (lost "Jean")
  2735	  RIGHT: FR "Levi's 501 Original Jean Coupe Droite" — "Jean" kept in both languages
  2736	  WRONG (EN has it, FR drops it): EN "Fjällräven Kånken Everyday Backpack" / FR "Fjällräven Kånken avec Tissu Vinylon F" (lost "Sac à dos")
  2737	  RIGHT: FR "Fjällräven Kånken Sac à Dos Vinylon F" — "Sac à dos" kept in both languages
  2738	
  2739	META DESCRIPTION RULES — MANDATORY, count characters before finishing: MINIMUM 150 chars, MAXIMUM 160 chars. 150 is a hard floor, not a suggestion — a meta_description under 150 chars is a failed response, rewrite it longer before responding.
  2740	- Start with an action verb in ${targetLang}
  2741	- One specific concrete benefit
  2742	${langCfg.cta ? `- End with: "${langCfg.cta}"` : '- No call to action'}
  2743	- If your draft is under 150 chars, add a second concrete benefit or spec before finalizing — never submit a short meta_description just because the first sentence felt complete.
  2744	  WRONG (too short, 120 chars): "Track performance across weeks of training with solar-extended battery life, multi-band GPS, and ECG monitoring built in"
  2745	  RIGHT (150-160 chars, same facts extended): "Track performance across weeks of training with solar-extended battery life, multi-band GPS, and ECG monitoring — built for serious athletes who need data they can trust."
  2746	
  2747	SELF-CHECK — SILENT INTERNAL REASONING ONLY. Do NOT write any of this out as text in your response. Do not write "Step 1", "SELF-CHECK", or any analysis before your answer. Consider these points internally, then respond with ONLY the ###TITLE### block below — nothing before it, no narration of your reasoning process.
  2748	
  2749	Step 1 — SPECS CHECK:
  2750	- Bullet 1 must contain a number or measurement (ml, cm, kg, pieces, hours...)
  2751	- If no measurement is known from the name or image, replace bullet 1 with a confirmed functional detail instead
  2752	- NEVER write vague bullets like "• Generous capacity" or "• Quality construction"
  2753	
  2754	Step 2 — REDUNDANCY CHECK:
  2755	- List every key noun and adjective you plan to use
  2756	- If any word repeats across title + prose + bullets + meta → replace the duplicate with a synonym
  2757	- Any material name: max 1 occurrence total across the entire output
  2758	- "quality" or its translation in ${targetLang}: max 1 occurrence total
  2759	- "design": max 1 occurrence total
  2760	
  2761	Step 3 — BULLET CHECK:
  2762	- Bullet 1: spec with number/measurement — if unknown, use the most specific confirmed functional detail
  2763	- Bullet 2: how the mechanism works (one concrete action)
  2764	- Bullet 3: design or emotional appeal (style, origin, feel) — no repeated adjectives from prose
  2765	- Bullet 4: care or warranty — write in ${targetLang} only. If dishwasher-safe is NOT confirmed, write a storage or warranty fact instead. NEVER invent care instructions.
  2766	- Each bullet max 12 words
  2767	
  2768	Step 4 — TONE CHECK:
  2769	- Every verb addressed to the customer must use "${langCfg.tone}" consistently — no mixing of formal/informal
  2770	
  2771	Your response starts IMMEDIATELY with ###TITLE### — the very first characters you output must be "###TITLE###", with no preamble, no self-check text, no explanation.
  2772	
  2773	Respond ONLY in this exact format, no JSON, no markdown backticks, no extra commentary before or after:
  2774	###TITLE###
  2775	the title here, one line
  2776	###DESCRIPTION###
  2777	the full description here, exactly as specified above — real line breaks between the intro and each bullet are fine and expected, do not escape anything
  2778	###META_TITLE###
  2779	the meta title here
  2780	###META_DESCRIPTION###
  2781	the meta description here
  2782	###END###`;
  2783	
  2784	  // Translation-mode rules — sharedRules minus CATEGORY KNOWLEDGE (STEP A/B/C +
  2785	  // category-specific spec blocks). When the merchant already wrote a description,
  2786	  // Haiku is translating EXISTING text, not generating specs from scratch — it
  2787	  // doesn't need to know what specs SHOULD exist, only how to render what's
  2788	  // already there (tone, unit conversion, SEO meta, self-check). This cuts the
  2789	  // prompt from ~6,957 to ~1,062 tokens for the majority of locale calls.
  2790	  const catStart = sharedRules.indexOf('CATEGORY KNOWLEDGE RULE:');
  2791	  const catEnd = sharedRules.indexOf('META TITLE RULES');
  2792	  const translationRules = (catStart >= 0 && catEnd > catStart)
  2793	    ? sharedRules.slice(0, catStart) + sharedRules.slice(catEnd)
  2794	    : sharedRules; // fallback — never breaks if markers shift
  2795	
  2796	  let isTranslation = false;
  2797	  let firstViolation = null;
  2798	
  2799	  if (hasImage && !cleanBody) {
  2800	    // GJENERIM I PARE me imazh — Claude Sonnet 4.6 (vizion), STEP A/B/C te plota
  2801	    const titleSection = product.title
  2802	      ? `Product name: "${product.title}"\n${category ? `Category: ${category}\n` : ''}${tags ? `Tags: ${tags}\n` : ''}`
  2803	      : `No product name provided. Identify the product from the image and write an appropriate name in ${targetLang}.`;
  2804	
  2805	    const contextBlock = `You are a native ${targetLang} speaker and professional ecommerce copywriter. Analyze the product image carefully.
  2806	
  2807	Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
  2808	Target language: ${targetLang}
  2809	
  2810	${titleSection}
  2811	${confirmedSpecsBlock}
  2812	Look carefully at the image. Identify ONLY what is clearly visible: materials, colors, shape, dimensions, text/branding, use case.
  2813	Do NOT invent specifications that are not visible or stated.`;
  2814	
  2815	    // sharedRules varet vetem nga targetLang/langCfg/kategoria (jo produkti/imazhi) —
  2816	    // i pari + cache_control: produkte te tjera te NJEJTES gjuhe+kategori (brenda 5 min) -90%
  2817	    userContent = [
  2818	      { type: 'text', text: sharedRules, cache_control: { type: 'ephemeral' } },
  2819	      { type: 'image', source: { type: 'url', url: imageUrl } },
  2820	      { type: 'text', text: contextBlock }
  2821	    ];
  2822	  } else if (cleanBody) {
  2823	    // PERKTHIM — Gemini 3.1 Flash-Lite. "cleanBody" ketu mund te jete ose
  2824	    // pershkrim i shkruar nga shitesi, ose gjenerimi i pare i AI-t (Sonnet) i
  2825	    // ruajtur tashme ne Shopify body_html nga nje lokale e meparshme e ketij
  2826	    // produkti (shih primaryCopy/updateShopifyProductBodyIfEmpty ne localizeProduct).
  2827	    // Te dyja jane "perkthim i nje teksti ekzistues", jo "gjenerim" — Sonnet
  2828	    // s'nevojitet, dhe e njejta translationRules (rregullat e tonit/SEO per
  2829	    // gjuhe) perdoret pavaresisht se cili provider e ekzekuton.
  2830	    isTranslation = true;
  2831	    const contextBlock = `You are a native ${targetLang} speaker and professional ecommerce translator.
  2832	
  2833	Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
  2834	Target language: ${targetLang}
  2835	
  2836	Translate this product description faithfully into ${targetLang}.
  2837	
  2838	STRICT RULES — violating any of these is a critical error:
  2839	1. TRANSLATE ONLY — do not add ANY information not present in the source text
  2840	2. NEVER add battery life in hours, screen brightness, weight, storage, or any numeric spec not in the source
  2841	3. If source says "5000mAh battery" → translate only that, do NOT add "24 hours autonomy"
  2842	4. If source says "octa-core" → do NOT add chip name not in source
  2843	5. Preserve ALL bullet points (•) and line breaks exactly as in source
  2844	6. Keep all numbers, units, model names exactly as written
  2845	7. Return ONLY the translated text — no explanations, no additions
  2846	
  2847	TITLE: ${product.title}
  2848	DESCRIPTION: ${cleanBody}
  2849	
  2850	TRANSLATION RULES:
  2851	- Translate the title naturally into ${targetLang}
  2852	- If the original has bullets keep bullets, if prose keep prose
  2853	- Apply the tone "${langCfg.tone}" consistently throughout
  2854	- Use sensory words where natural: ${langCfg.sensoryWords}
  2855	- Avoid: ${langCfg.avoidWords}`;
  2856	
  2857	    // Gemini pranon nje string te vetem teksti (jo array blloqesh si Claude) —
  2858	    // pa cache_control, sepse caching i Gemini punon ndryshe (shih /docs/caching)
  2859	    // dhe per vellimin aktual te perkthimeve s'ia vlen kompleksiteti shtese.
  2860	    userContent = `${translationRules}\n\n${contextBlock}`;
  2861	  } else {
  2862	    // GJENERIM I PARE nga titulli, pa imazh — Claude Sonnet 4.6, STEP A/B/C te plota
  2863	    const contextBlock = `You are a native ${targetLang} speaker and professional ecommerce copywriter.
  2864	
  2865	Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
  2866	Target language: ${targetLang}
  2867	
  2868	Product name: "${product.title}"
  2869	${category ? `Category: ${category}` : ''}
  2870	${tags ? `Tags: ${tags}` : ''}
  2871	${confirmedSpecsBlock}
  2872	No description exists. Write product copy in ${targetLang} based ONLY on the product name above — no invention.`;
  2873	
  2874	    userContent = [
  2875	      { type: 'text', text: sharedRules, cache_control: { type: 'ephemeral' } },
  2876	      { type: 'text', text: contextBlock }
  2877	    ];
  2878	  }
  2879	
  2880	  console.log(`[provider] ${isTranslation ? 'gemini-3.1-flash-lite (perkthim)' : 'claude-sonnet-4-6 (gjenerim i pare)'} — image:${hasImage} body:${!!cleanBody} product:"${product.title}"`);
  2881	
  2882	  try {
  2883	    let rawText = '';
  2884	    // Format i ri me shenues (###TITLE### etj) ne vend te JSON — eliminon
  2885	    // teresisht klasen e gabimeve qe kishim me JSON.parse() (newline real,
  2886	    // thonjeza te pa-escape-uara, apostrofa brenda description-it). Modeli
  2887	    // shkruan tekst te lire mes shenuesve, ne s'kerkojme fare qe te
  2888	    // escape-oje asgje — thjesht presim ku fillon dhe mbaron cdo fushe.
  2889	    const extractJson = (text) => {
  2890	      const clean = text.replace(/```[a-z]*\n?/g, '').trim();
  2891	      const getSection = (startMarker, endMarkers) => {
  2892	        const startIdx = clean.indexOf(startMarker);
  2893	        if (startIdx === -1) return null;
  2894	        const contentStart = startIdx + startMarker.length;
  2895	        let endIdx = clean.length;
  2896	        for (const marker of endMarkers) {
  2897	          const idx = clean.indexOf(marker, contentStart);
  2898	          if (idx !== -1 && idx < endIdx) endIdx = idx;
  2899	        }
  2900	        return clean.slice(contentStart, endIdx).trim();
  2901	      };
  2902	      const title = getSection('###TITLE###', ['###DESCRIPTION###', '###META_TITLE###', '###META_DESCRIPTION###', '###END###']);
  2903	      const description = getSection('###DESCRIPTION###', ['###META_TITLE###', '###META_DESCRIPTION###', '###END###']);
  2904	      const meta_title = getSection('###META_TITLE###', ['###META_DESCRIPTION###', '###END###']);
  2905	      const meta_description = getSection('###META_DESCRIPTION###', ['###END###']);
  2906	      if (!title || !description) return null;
  2907	      return { title, description, meta_title: meta_title || '', meta_description: meta_description || '' };
  2908	    };
  2909	
  2910	    if (isTranslation) {
  2911	      const geminiRes = await axios.post(
  2912	        'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent',
  2913	        {
  2914	          contents: [{ parts: [{ text: userContent }] }],
  2915	          generationConfig: { maxOutputTokens: 1500, temperature: 0 }
  2916	        },
  2917	        {
  2918	          headers: {
  2919	            'x-goog-api-key': process.env.GEMINI_API_KEY,
  2920	            'content-type': 'application/json'
  2921	          },
  2922	          timeout: 45000
  2923	        }
  2924	      );
  2925	      rawText = geminiRes.data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  2926	    } else {
  2927	      const callSonnet = async (content) => {
  2928	        const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
  2929	          model: 'claude-sonnet-4-6',
  2930	          max_tokens: 2500,
  2931	          temperature: 0,
  2932	          messages: [{ role: 'user', content }]
  2933	        }, {
  2934	          headers: {
  2935	            'x-api-key': process.env.ANTHROPIC_API_KEY,
  2936	            'anthropic-version': '2023-06-01',
  2937	            'content-type': 'application/json'
  2938	          },
  2939	          timeout: 45000
  2940	        });
  2941	        let text = '';
  2942	        for (const block of claudeRes.data.content) {
  2943	          if (block.type === 'text') text += block.text;
  2944	        }
  2945	        return text;
  2946	      };
  2947	
  2948	      rawText = await callSonnet(userContent);
  2949	
  2950	      // Rrjeta e sigurise mekanike: nese s'ka konfirmim te jashtem dhe Sonnet
  2951	      // prape shkroi numra te "zhveshur" OSE emer çipi me brez specifik (shkeli
  2952	      // EXTERNAL CONFIRMATION STATUS ne favor te STEP A "MANDATORY" — shih
  2953	      // rastin MacBook Neo), provo NJE here te dyte me korrigjim te forte te
  2954	      // shtuar, ne vend qe pergjigja e gabuar te shkoje direkt te shitesi.
  2955	      if (!hasExternalConfirmation) {
  2956	        let firstParsed;
  2957	        try { firstParsed = extractJson(rawText); } catch { firstParsed = null; }
  2958	
  2959	        firstViolation = firstParsed?.description ? detectGateViolation(firstParsed.description, targetLang) : null;
  2960	        if (firstViolation) {
  2961	          console.warn(`[gate-violation] Sonnet shkeli gate-in (${firstViolation}) per "${product.title}" (${targetLang}) — duke provuar korrigjim`);
  2962	          const correction = {
  2963	            type: 'text',
  2964	            text: `Your previous response violated a critical rule: it stated exact numeric specs (RAM, storage, screen size, battery, etc.) OR a specific chip/processor generation name (e.g. "A18", "Snapdragon 8 Elite") as confirmed facts, even though there is NO external confirmation for this product (no title override, no metafields). Rewrite the ENTIRE response. Every single numeric spec MUST use "up to" / "${UP_TO_HEDGES[targetLang]?.display || 'up to'}" framing or be omitted. Any chip/processor MUST be described generically (e.g. "Apple silicon chip", "octa-core processor") WITHOUT the generation number, unless it cannot be phrased that way, in which case omit it. Respond ONLY with the corrected version, same ###TITLE###/###DESCRIPTION###/###META_TITLE###/###META_DESCRIPTION###/###END### format as before.`
  2965	          };
  2966	          rawText = await callSonnet([...userContent, correction]);
  2967	        }
  2968	      }
  2969	    }
  2970	
  2971	    const parsed = extractJson(rawText);
  2972	    if (!parsed) {
  2973	      console.error(`[json-parse] Deshtoi per "${product.title}" — rawText[0:300]: ${rawText.slice(0, 300)}`);
  2974	      throw new Error(`No ###TITLE###/###DESCRIPTION### markers found in ${isTranslation ? 'Gemini' : 'Claude'} response`);
  2975	    }
  2976	    if (!parsed.title || !parsed.description) throw new Error('Missing title or description');
  2977	
  2978	    if (!isTranslation && !hasExternalConfirmation && firstViolation) {
  2979	      const stillViolating = detectGateViolation(parsed.description, targetLang);
  2980	      if (stillViolating) {
  2981	        console.warn(`[gate-violation] Vazhdoi pas korrigjimit (${stillViolating}) per "${product.title}" — duke ruajtur prape, shiko logs per monitorim`);
  2982	      }
  2983	      logGateViolation(shop, product, targetLang, firstViolation, !stillViolating);
  2984	    }
  2985	
  2986	    // Shtresa e fundit deterministike: pavaresisht nese retry-i sipër ekzistoi
  2987	    // fare, e zgjidhi, ose dështoi pjesërisht, ÇDO numer specifikash i mbetur
  2988	    // pa "deri ne" detyrohet mekanikisht ketu. Garanci, jo shprese.
  2989	    if (!isTranslation && !hasExternalConfirmation) {
  2990	      parsed.description = forceHedgeSpecNumbers(parsed.description, targetLang);
  2991	    }
  2992	
  2993	    return parsed;
  2994	  } catch (apiErr) {
  2995	    // Dikur kthente product.title si "perkthim" gjatë dështimit të Gemini/Claude,
  2996	    // duke e ruajtur si status:'done' — kjo maskonte dështimin real dhe shkaktonte
  2997	    // pikërisht simptomën: flamuri FR shfaqej "Localized" por përmbajtja mbetej
  2998	    // anglisht. Tani hidhet error real — localizeProductBody/localizeProduct e
  2999	    // kap, fshin lock-un 'processing', dhe e lejon riprovim në ciklin tjetër
  3000	    // (poll ose webhook retry), në vend që të ruajë të dhëna të gabuara si sukses.
  3001	    console.error(`${isTranslation ? 'Gemini' : 'Claude'} API failed:`, apiErr.response?.data || apiErr.message);
  3002	    throw new Error(`${isTranslation ? 'Gemini' : 'Claude'} translation failed: ${apiErr.response?.data?.error?.message || apiErr.message}`);
  3003	  }
  3004	}
  3005	
  3006	
  3007	async function localizeProduct(shop, token, productId, targetLang, locale, tone, glossary) {
  3008	  const pid = normalizeProductId(productId);
  3009	
  3010	  // Kontroll i fundit i limitit — brenda localizeProduct() per te bllokuar
  3011	  // çdo rruge (poll, webhook, /localize, /process-product) pavarësisht.
  3012	  const PLANS = app.locals.PLANS;
  3013	  if (PLANS) {
  3014	    try {
  3015	      const store = await getStore(shop);
  3016	      if (store) {
  3017	        const planName = store.plan || 'free';
  3018	        const plan = PLANS[planName] || PLANS.free;
  3019	        const planStartedAt = store.plan_started_at || null;
  3020	        let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(10000);
  3021	        if (planStartedAt) q = q.gte('created_at', planStartedAt);
  3022	        const { data: rows } = await q;
  3023	        const existingIds = new Set((rows || []).map(r => String(r.product_id)));
  3024	        if (!existingIds.has(String(pid)) && existingIds.size >= plan.product_limit) {
  3025	          console.warn(`[plan-limit] localizeProduct blocked: ${shop} ${planName} limit ${plan.product_limit}, used ${existingIds.size}, product ${pid}`);
  3026	          throw new Error(`PLAN_LIMIT: Your ${plan.label} plan supports ${plan.product_limit} products. Upgrade at ${process.env.APP_URL}/pricing?shop=${shop}`);
  3027	        }
  3028	      }
  3029	    } catch(limitErr) {
  3030	      if (limitErr.message.startsWith('PLAN_LIMIT')) throw limitErr;
  3031	      console.warn('[plan-limit] check failed silently:', limitErr.message);
  3032	    }
  3033	  }
  3034	
  3035	  // ─── PROCESSING LOCK ──────────────────────────────────────────────────────
  3036	  // Mbron nga race condition mes 5 pikave hyrjeje te pavarura (webhook, poll,
  3037	  // /localize, /process-product, bulk-localize-all). Pa kete, te gjitha
  3038	  // kontrollojne tabelen 'translations' PARA se te fillojne, por rreshti
  3039	  // shkruhet vetem ne FUND te funksionit (pas Tavily+Sonnet+Shopify push,
  3040	  // 10-15s). Ne ate dritare kohore, cdo pike tjeter hyrjeje sheh gjithashtu
  3041	  // "s'ka translation ende" dhe fillon vet gjenerimin nga zero — duke
  3042	  // shpenzuar Tavily/Sonnet/Gemini credits te dyfishta/trefishta per te
  3043	  // njejtin (produkt, gjuhe). INSERT (jo upsert) eshte atomik ne Postgres:
  3044	  // unique constraint mbi (shop, product_id, locale) — e njejta qe perdor
  3045	  // upsert-i final me poshte via onConflict — ben qe VETEM NJE thirrje
  3046	  // konkurruese te fitoje rreshtin; te tjerat marrin gabim 23505 (duplicate
  3047	  // key) dhe dalin menjehere, PARA se te thirret Tavily ose Sonnet fare.
  3048	  //
  3049	  // STALE LOCK RECOVERY: webhook e ekzekuton gjenerimin brenda setImmediate()
  3050	  // PAS res.send() — Vercel s'e garanton perfundimin e ekzekutimit ne sfond,
  3051	  // dhe mund ta ndaloje funksionin me force (kalim kohe limiti, sidomos me 5+
  3052	  // gjuhe njepasnjeshme). Ne ate rast, catch-i i localizeProduct kurre s'arrin
  3053	  // te fshije lock-un — rreshti 'processing' mbetet i bllokuar PERGJITHMONE.
  3054	  // Nese lock ekzistues eshte me i vjeter se PROCESSING_LOCK_STALE_MS, e
  3055	  // trajtojme si ekzekutim i vdekur dhe lejojme riprovim ne vend qe produkti
  3056	  // te mos lokalizohet kurre me.
  3057	  const PROCESSING_LOCK_STALE_MS = 3 * 60 * 1000; // 3 min
  3058	  const { data: existingLockRow } = await supabase
  3059	    .from('translations')
  3060	    .select('status, created_at')
  3061	    .eq('shop', shop).eq('product_id', pid).eq('locale', locale)
  3062	    .maybeSingle();
  3063	
  3064	  if (existingLockRow?.status === 'processing') {
  3065	    const ageMs = Date.now() - new Date(existingLockRow.created_at).getTime();
  3066	    if (ageMs < PROCESSING_LOCK_STALE_MS) {
  3067	      console.log(`[lock] ${pid}/${locale} per ${shop} — tashme po procesohet (${Math.round(ageMs/1000)}s), anashkalohet`);
  3068	      return { product_id: pid, skipped: true, reason: 'already_processing' };
  3069	    }
  3070	    console.warn(`[lock] ${pid}/${locale} per ${shop} — lock 'processing' i vjeter (${Math.round(ageMs/1000)}s, ekzekutim i vdekur me siguri) — riprovohet`);
  3071	    await supabase.from('translations').delete()
  3072	      .eq('shop', shop).eq('product_id', pid).eq('locale', locale).eq('status', 'processing');
  3073	  }
  3074	
  3075	  const { error: lockError } = await supabase
  3076	    .from('translations')
  3077	    .insert({
  3078	      shop, product_id: pid, locale, status: 'processing',
  3079	      original_title: '', original_description: '', product_handle: '',
  3080	      translated_title: '', translated_description: ''
  3081	    });
  3082	  if (lockError) {
  3083	    if (lockError.code === '23505') {
  3084	      console.log(`[lock] ${pid}/${locale} per ${shop} — tashme po procesohet nga nje thirrje tjeter, anashkalohet`);
  3085	      return { product_id: pid, skipped: true, reason: 'already_processing' };
  3086	    }
  3087	    console.warn('[lock] Insert deshtoi per arsye tjeter (jo duplicate) — vazhdoj pa lock:', lockError.message);
  3088	  }
  3089	
  3090	  try {
  3091	    return await localizeProductBody(shop, token, pid, targetLang, locale, tone, glossary);
  3092	  } catch (bodyErr) {
  3093	    // Nese lock-u u fitua nga KJO thirrje (jo dikush tjeter) dhe gjenerimi
  3094	    // deshtoi, fshi rreshtin 'processing' qe produkti te mund te riprovohet
  3095	    // ne thirrjen tjeter (poll cikli tjeter, webhook retry) — perndryshe
  3096	    // mbetet "bllokuar" perfundimisht si i papërfunduar, dhe s'lokalizohet
  3097	    // asnjehere me.
  3098	    if (!lockError) {
  3099	      await supabase.from('translations')
  3100	        .delete()
  3101	        .eq('shop', shop).eq('product_id', pid).eq('locale', locale).eq('status', 'processing')
  3102	        .then(() => {})
  3103	        .catch(() => {});
  3104	    }
  3105	    throw bodyErr;
  3106	  }
  3107	}
  3108	
  3109	async function localizeProductBody(shop, token, pid, targetLang, locale, tone, glossary) {
  3110	  const productRes = await axios.get(
  3111	    `https://${shop}/admin/api/2024-01/products/${pid}.json`,
  3112	    { headers: { 'X-Shopify-Access-Token': token } }
  3113	  );
  3114	  const product = productRes.data.product;
  3115	
  3116	  const digestQuery = `
  3117	    query getTranslatableContent($resourceId: ID!) {
  3118	      translatableResource(resourceId: $resourceId) {
  3119	        translatableContent { key value digest locale }
  3120	      }
  3121	    }
  3122	  `;
  3123	  const digestRes = await axios.post(
  3124	    `https://${shop}/admin/api/2024-01/graphql.json`,
  3125	    { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${pid}` } },
  3126	    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  3127	  );
  3128	  const contents = digestRes.data.data.translatableResource.translatableContent;
  3129	  const digests = {};
  3130	  contents.forEach(c => { digests[c.key] = c.digest; });
  3131	
  3132	  // Merr metafields te produktit
  3133	  let metafields = [];
  3134	  try {
  3135	    const mfRes = await axios.get(
  3136	      `https://${shop}/admin/api/2024-01/products/${pid}/metafields.json`,
  3137	      { headers: { 'X-Shopify-Access-Token': token } }
  3138	    );
  3139	    metafields = (mfRes.data.metafields || []).filter(mf =>
  3140	      typeof mf.value === 'string' && mf.value.trim().length > 0 &&
  3141	      mf.value.trim().length <= 200 && // skip long fields (e.g. INCI ingredient lists — international standard, same across languages, expensive to translate)
  3142	      !['integer','boolean','json','number_integer','number_decimal','url','color','date','date_time','weight','volume','dimension','rating'].includes(mf.type)
  3143	    );
  3144	    if (metafields.length > 0) console.log(`[metafields] Found ${metafields.length} for "${product.title}"`);
  3145	  } catch(mfErr) {
  3146	    console.warn('[metafields] Fetch failed:', mfErr.message);
  3147	  }
  3148	
  3149	  const cleanBody = (product.body_html || '').replace(/<[^>]*>/g, '').trim();
  3150	  const hadNoDescription = !cleanBody;
  3151	
  3152	  // Nxjerr URL-in e imazhit te pare (nese ekziston) — perdoret per Sonnet 4.6
  3153	  const imageUrl = product.images && product.images.length > 0
  3154	    ? product.images[0].src
  3155	    : null;
  3156	  if (imageUrl && !cleanBody) {
  3157	    console.log(`[image] "${product.title}" has image + no body — routing to Sonnet 4.6`);
  3158	  }
  3159	
  3160	  let translated = await generateProductCopy(product, targetLang, glossary, cleanBody, imageUrl, metafields, shop);
  3161	
  3162	  // Perkthej metafields
  3163	  const translatedMetafields = [];
  3164	  if (metafields.length > 0) {
  3165	    for (const mf of metafields.slice(0, 10)) { // max 10 metafields per produkt
  3166	      try {
  3167	        const translatedValue = await translateFieldWithGemini(mf.value, mf.key, targetLang);
  3168	        translatedMetafields.push({ ...mf, translatedValue });
  3169	        console.log(`[metafields] Translated "${mf.key}" → ${targetLang} (Gemini)`);
  3170	      } catch(e) {
  3171	        console.warn(`[metafields] Translation failed for "${mf.key}":`, e.message);
  3172	      }
  3173	      await new Promise(r => setTimeout(r, 200));
  3174	    }
  3175	  }
  3176	
  3177	  if (!translated.meta_title) {
  3178	    translated.meta_title = (translated.title || product.title).substring(0, 60);
  3179	  }
  3180	  if (!translated.meta_description) {
  3181	    translated.meta_description = (translated.description || translated.title || product.title).substring(0, 160);
  3182	  }
  3183	
  3184	  // Primary locale duhet marre GJITHMONE (jo vetem brenda hadNoDescription) —
  3185	  // nevojitet per te ditur nese target locale eshte njesoj si primary locale
  3186	  // i dyqanit. Nese po, Shopify REFUZON translationsRegister mutation me
  3187	  // gabim "Locale cannot be the same as the shop's primary locale" — s'ka
  3188	  // kuptim te "perkthesh" ne gjuhen qe eshte tashme primare e dyqanit.
  3189	  let primaryLocale = null;
  3190	  try {
  3191	    primaryLocale = await getPrimaryLocale(shop, token);
  3192	  } catch(e) {
  3193	    console.warn('[primary-locale] Fetch failed, assuming target is not primary:', e.message);
  3194	  }
  3195	  const isTargetPrimaryLocale = !!primaryLocale && locale.split('-')[0] === primaryLocale.split('-')[0];
  3196	
  3197	  // Kontroll shtese: target locale duhet te jete i konfiguruar te vete
  3198	  // Shopify (Settings → Languages), jo vetem i zgjedhur te Getoify. Keto
  3199	  // jane dy sisteme te ndryshme — merchant mund te zgjedhe FR te Getoify
  3200	  // pa e shtuar ende FR te gjuhet e dyqanit, dhe Shopify e refuzon
  3201	  // translationsRegister me "Locale is not a valid locale for the shop".
  3202	  let isTargetLocaleConfigured = true;
  3203	  try {
  3204	    const allLocalesQuery = `query { shopLocales { locale } }`;
  3205	    const allLocalesRes = await axios.post(
  3206	      `https://${shop}/admin/api/2024-01/graphql.json`,
  3207	      { query: allLocalesQuery },
  3208	      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  3209	    );
  3210	    const configuredLocales = (allLocalesRes.data.data?.shopLocales || []).map(l => l.locale);
  3211	    isTargetLocaleConfigured = configuredLocales.some(l => l.split('-')[0] === locale.split('-')[0]);
  3212	    if (!isTargetLocaleConfigured) {
  3213	      console.warn(`[locale] ${locale} s'eshte konfiguruar te gjuhet e ${shop} (Settings → Languages) — anashkalohet translationsRegister`);
  3214	    }
  3215	  } catch(e) {
  3216	    console.warn('[locale] Fetch i gjuheve te konfiguruara deshtoi, vazhdon normalisht:', e.message);
  3217	  }
  3218	
  3219	  if (hadNoDescription) {
  3220	    try {
  3221	      const localeKey = locale.split('-')[0];
  3222	      const primaryKey = (primaryLocale || 'en').split('-')[0];
  3223	      let bodyForShopify = translated.description;
  3224	      if (localeKey !== primaryKey) {
  3225	        const primaryLang = LOCALE_MAP[primaryKey] || primaryLocale;
  3226	        console.log(`[primaryCopy] Duke perkthyer per gjuhen primare (${primaryLang}) direkt ne Gemini`);
  3227	        bodyForShopify = await translatePrimaryDescriptionWithGemini(translated.description, primaryLang, glossary);
  3228	      }
  3229	      const bodyUpdated = await updateShopifyProductBodyIfEmpty(shop, token, pid, bodyForShopify);
  3230	      if (bodyUpdated) {
  3231	        // Re-fetch digests so body_html digest is available for translation registration
  3232	        const freshDigestRes = await axios.post(
  3233	          `https://${shop}/admin/api/2024-01/graphql.json`,
  3234	          { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${pid}` } },
  3235	          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  3236	        );
  3237	        const freshContents = freshDigestRes.data.data.translatableResource.translatableContent;
  3238	        freshContents.forEach(c => { digests[c.key] = c.digest; });
  3239	        console.log('Re-fetched digests after body_html update, body_html digest:', digests['body_html']);
  3240	      }
  3241	    } catch (bodyErr) {
  3242	      console.error('Failed to update Shopify body_html:', bodyErr.response?.data || bodyErr.message);
  3243	    }
  3244	  }
  3245	
  3246	  const mutation = `
  3247	    mutation translationsRegister($resourceId: ID!, $translations: [TranslationInput!]!) {
  3248	      translationsRegister(resourceId: $resourceId, translations: $translations) {
  3249	        translations { key value }
  3250	        userErrors { field message }
  3251	      }
  3252	    }
  3253	  `;
  3254	  // Nese target locale = primary locale i dyqanit, Shopify refuzon CDO
  3255	  // translationsRegister per kete resource — anashkalohet plotesisht.
  3256	  // body_html tashme u perditesua direkt me siper (updateShopifyProductBodyIfEmpty)
  3257	  // kur hadNoDescription=true. Titulli mbetet i pandryshuar per gjuhen primare
  3258	  // (Sonnet s'e ndryshon titullin origjinal). meta_title/meta_description per
  3259	  // primary locale kerkojne mutation tjeter (Product Update, jo Translations
  3260	  // API) — mbetet permirsim i ardhshem, s'trajtohet ketu.
  3261	  let pushRes = null;
  3262	  if (isTargetPrimaryLocale) {
  3263	    console.log(`[locale] ${locale} eshte primary locale i ${shop} — anashkalohet translationsRegister`);
  3264	  } else if (!isTargetLocaleConfigured) {
  3265	    console.log(`[locale] ${locale} s'eshte konfiguruar te ${shop} — anashkalohet translationsRegister`);
  3266	  } else {
  3267	    pushRes = await axios.post(
  3268	    `https://${shop}/admin/api/2024-01/graphql.json`,
  3269	    {
  3270	      query: mutation,
  3271	      variables: {
  3272	        resourceId: `gid://shopify/Product/${pid}`,
  3273	        translations: [
  3274	          { key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] },
  3275	          ...(digests['body_html']
  3276	            ? [{ key: 'body_html', value: translated.description, locale, translatableContentDigest: digests['body_html'] }]
  3277	            : []),
  3278	          // meta_title: push ONLY if Shopify has its own digest — fallback digest causes "hash invalid" error
  3279	          ...(translated.meta_title && digests['meta_title'] ? [{ key: 'meta_title', value: translated.meta_title, locale, translatableContentDigest: digests['meta_title'] }] : []),
  3280	          // meta_description: push ONLY if Shopify has its own digest — fallback digest causes "hash invalid" error
  3281	          ...(translated.meta_description && digests['meta_description'] ? [{ key: 'meta_description', value: translated.meta_description, locale, translatableContentDigest: digests['meta_description'] }] : [])
  3282	        ]
  3283	      }
  3284	    },
  3285	    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  3286	    );
  3287	  }
  3288	
  3289	  await supabase.from('translations').upsert({
  3290	    shop,
  3291	    product_id: pid,
  3292	    locale,
  3293	    status: 'done',
  3294	    original_title: product.title,
  3295	    original_description: product.body_html || '',
  3296	    product_handle: product.handle || '',
  3297	    translated_title: translated.title,
  3298	    translated_description: translated.description,
  3299	    meta_title: translated.meta_title,
  3300	    meta_description: translated.meta_description
  3301	  }, { onConflict: 'shop,product_id,locale' });
  3302	
  3303	  // Regjistro metafield translations te Shopify — anashkalohet per primary locale
  3304	  // (i njejti kufizim si mutation-i kryesor: Shopify s'lejon "perkthim" ne
  3305	  // gjuhen qe eshte tashme primare).
  3306	  if (translatedMetafields.length > 0 && !isTargetPrimaryLocale) {
  3307	    for (const mf of translatedMetafields) {
  3308	      try {
  3309	        const mfResourceId = `gid://shopify/Metafield/${mf.id}`;
  3310	        // Merr digest per kete metafield
  3311	        const mfDigestRes = await axios.post(
  3312	          `https://${shop}/admin/api/2024-01/graphql.json`,
  3313	          { query: digestQuery, variables: { resourceId: mfResourceId } },
  3314	          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  3315	        );
  3316	        const mfContents = mfDigestRes.data.data?.translatableResource?.translatableContent || [];
  3317	        const mfDigest = mfContents.find(c => c.key === 'value')?.digest;
  3318	        if (!mfDigest) { console.warn(`[metafields] No digest for ${mf.key}`); continue; }
  3319	        await axios.post(
  3320	          `https://${shop}/admin/api/2024-01/graphql.json`,
  3321	          {
  3322	            query: mutation,
  3323	            variables: {
  3324	              resourceId: mfResourceId,
  3325	              translations: [{ key: 'value', value: mf.translatedValue, locale, translatableContentDigest: mfDigest }]
  3326	            }
  3327	          },
  3328	          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  3329	        );
  3330	        console.log(`[metafields] Registered: ${mf.key} → ${locale}`);
  3331	      } catch(e) {
  3332	        console.warn(`[metafields] Register failed for "${mf.key}":`, e.message);
  3333	      }
  3334	    }
  3335	  }
  3336	
  3337	  // Log Shopify response për debugging — pushRes eshte null nese isTargetPrimaryLocale
  3338	  const shopifyResult = pushRes ? pushRes.data.data?.translationsRegister : null;
  3339	  if (shopifyResult?.userErrors?.length > 0) {
  3340	    console.error('Shopify userErrors:', JSON.stringify(shopifyResult.userErrors));
  3341	  } else if (shopifyResult) {
  3342	    console.log('Shopify translations pushed OK:', shopifyResult?.translations?.length, 'fields');
  3343	  }
  3344	
  3345	  console.log('Saved translation:', { shop, product_id: pid, locale, title: product.title });
  3346	
  3347	  return { product_id: pid, product: product.title, translated, shopify: shopifyResult };
  3348	}
  3349	
  3350	app.post('/localize', requireShopAuth, async (req, res) => {
  3351	  const shop = req.verifiedShop;
  3352	  const { productId, targetLang, locale, tone, glossary } = req.body;
  3353	  try {
  3354	    const pid = normalizeProductId(productId);
  3355	
  3356	    // Kontroll limiti para gjenerimit — /localize eshte endpoint qe
  3357	    // theret nga dashboard kur merchant klikon "Translate" per nje produkt
  3358	    const store = await getStore(shop);
  3359	    // SSRF/trust fix: token nuk pranohet me nga trupi i kerkeses — shop
  3360	    // tashme eshte i verifikuar, pra token-i real merret nga i njejti
  3361	    // getStore(shop) i thirrur me lart (nuk shton nje thirrje shtese ne DB).
  3362	    const token = store?.access_token;
  3363	    if (!token) return res.status(400).json({ error: 'Store not connected or token missing' });
  3364	    const PLANS = app.locals.PLANS;
  3365	    if (PLANS && store) {
  3366	      const planName = store.plan || 'free';
  3367	      const plan = PLANS[planName] || PLANS.free;
  3368	      const planStartedAt = store.plan_started_at || null;
  3369	      let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(10000);
  3370	      if (planStartedAt) q = q.gte('created_at', planStartedAt);
  3371	      const { data: rows } = await q;
  3372	      const existingIds = new Set((rows || []).map(r => String(r.product_id)));
  3373	      // Nese ky produkt eshte i ri (jo i perkthyer me pare) dhe kemi arritur limitin
  3374	      if (!existingIds.has(String(pid)) && existingIds.size >= plan.product_limit) {
  3375	        console.warn(`[plan-limit] /localize blocked for ${shop} — ${planName} limit (${plan.product_limit}, used ${existingIds.size})`);
  3376	        return res.status(403).json({
  3377	          error: `Plan limit reached. Your ${plan.label} plan supports ${plan.product_limit} products. Upgrade to continue.`,
  3378	          upgrade_url: `${process.env.APP_URL}/pricing?shop=${shop}`,
  3379	          plan: planName,
  3380	          limit: plan.product_limit,
  3381	          used: existingIds.size
  3382	        });
  3383	      }
  3384	    }
  3385	
  3386	    const result = await localizeProduct(shop, token, pid, targetLang, locale, tone, glossary);
  3387	    res.json({ success: true, product_id: pid, ...result });
  3388	  } catch (error) {
  3389	    res.status(500).json({ error: error.message });
  3390	  }
  3391	});
  3392	
  3393	
  3394	app.post('/bulk-localize-collections', requireShopAuth, async (req, res) => {
  3395	  const shop = req.verifiedShop;
  3396	  const { token, glossary } = req.body;
  3397	  try {
  3398	    const store = await getStore(shop);
  3399	    const savedLocales = store.selected_locales || [];
  3400	    const tok = token || store.access_token;
  3401	    const results = await bulkLocalizeCollections(shop, tok, store.tone, glossary || store.glossary, savedLocales);
  3402	    res.json({ success: true, results });
  3403	  } catch(e) { res.status(500).json({ error: e.message }); }
  3404	});
  3405	
  3406	app.post('/bulk-localize-blogs', requireShopAuth, async (req, res) => {
  3407	  const shop = req.verifiedShop;
  3408	  const { token, glossary } = req.body;
  3409	  try {
  3410	    const store = await getStore(shop);
  3411	    const savedLocales = store.selected_locales || [];
  3412	    const tok = token || store.access_token;
  3413	    const results = await bulkLocalizeBlogs(shop, tok, glossary || store.glossary, savedLocales);
  3414	    res.json({ success: true, results });
  3415	  } catch(e) { res.status(500).json({ error: e.message }); }
  3416	});
  3417	
  3418	app.post('/bulk-localize-all', requireShopAuth, async (req, res) => {
  3419	  const shop = req.verifiedShop;
  3420	  const { token, tone, glossary } = req.body;
  3421	  try {
  3422	    const store = await getStore(shop);
  3423	    const savedLocales = store.selected_locales || [];
  3424	
  3425	    // Hard plan limit — slice products to plan maximum
  3426	    const PLANS = app.locals.PLANS;
  3427	    let productLimit = 15; // free default
  3428	    let localeLimit = 2;
  3429	    let bulkLimit = 15; // free default
  3430	    if (PLANS) {
  3431	      const planName = store.plan || 'free';
  3432	      const plan = PLANS[planName] || PLANS.free;
  3433	      productLimit = plan.product_limit;
  3434	      localeLimit = plan.language_limit;
  3435	      bulkLimit = plan.bulk_limit !== undefined ? plan.bulk_limit : plan.product_limit;
  3436	      if (savedLocales.length > localeLimit) {
  3437	        console.warn(`[plan-limit] ${shop} has ${savedLocales.length} locales but plan allows ${localeLimit}`);
  3438	        savedLocales.splice(localeLimit);
  3439	      }
  3440	    }
  3441	    const locales = savedLocales.length > 0
  3442	      ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
  3443	      : await getShopLocales(shop, token);
  3444	    // Fetch all products with cursor pagination (supports 500+)
  3445	    let products = [];
  3446	    let bulkUrl = `https://${shop}/admin/api/2024-01/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;
  3447	    while (bulkUrl) {
  3448	      const batchRes = await axios.get(bulkUrl, {
  3449	        headers: { 'X-Shopify-Access-Token': token },
  3450	        timeout: SHOPIFY_PRODUCTS_TIMEOUT_MS
  3451	      });
  3452	      products = products.concat(batchRes.data.products || []);
  3453	      const linkHeader = batchRes.headers['link'] || '';
  3454	      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
  3455	      bulkUrl = nextMatch ? nextMatch[1] : null;
  3456	    }
  3457	
  3458	    // Enforce bulk limit — never translate more than bulk_limit in one run
  3459	    if (products.length > bulkLimit) {
  3460	      console.warn(`[bulk-limit] Slicing ${products.length} → ${bulkLimit} products for ${shop} (bulk_limit)`);
  3461	      products = products.slice(0, bulkLimit);
  3462	    }
  3463	
  3464	    // Skip produktet qe jane perkthyer tashme per ate gjuhe — kursen kosto API
  3465	    const { data: existingRows } = await supabase
  3466	      .from('translations')
  3467	      .select('product_id, locale')
  3468	      .eq('shop', shop);
  3469	    const translatedSet = new Set((existingRows || []).map(r => `${String(r.product_id)}:${r.locale}`));
  3470	    const existingProductIds = new Set((existingRows || []).map(r => String(r.product_id)));
  3471	
  3472	    const toTranslate = [];
  3473	    let trackedCount = existingProductIds.size; // produktet aktuale ne plan
  3474	    for (const product of products) {
  3475	      const pid = String(normalizeProductId(product.id));
  3476	      const missingLocales = locales.filter(l => !translatedSet.has(`${pid}:${l.locale}`));
  3477	      if (missingLocales.length === 0) continue;
  3478	
  3479	      const isNewProduct = !existingProductIds.has(pid);
  3480	      if (isNewProduct) {
  3481	        if (PLANS && trackedCount >= productLimit) {
  3482	          console.log(`[plan-limit] ${shop} reached ${productLimit} products — stopping bulk for new products`);
  3483	          break;
  3484	        }
  3485	        trackedCount++;
  3486	      }
  3487	      toTranslate.push({ product, missingLocales });
  3488	    }
  3489	    console.log(`[bulk] ${products.length} total — ${toTranslate.length} need translation — ${products.length - toTranslate.length} skipped`);
  3490	
  3491	    res.writeHead(200, { 'Content-Type': 'application/json' });
  3492	    res.write('{"results":[');
  3493	    let first = true;
  3494	    function writeResult(obj) {
  3495	      // Sinkron — pa 'await' brenda — pra e sigurt edhe kur disa produkte
  3496	      // po perpunohen njekohesisht (event loop i Node s'e nderpret kete blloku)
  3497	      if (!first) res.write(',');
  3498	      res.write(JSON.stringify(obj));
  3499	      first = false;
  3500	    }
  3501	
  3502	    async function processProductLocales(product, missingLocales) {
  3503	      const bulkPid = normalizeProductId(product.id);
  3504	      for (const lang of missingLocales) {
  3505	        try {
  3506	          const result = await localizeProduct(shop, token, bulkPid, lang.targetLang, lang.locale, tone, glossary);
  3507	          writeResult({ success: true, product_id: bulkPid, locale: lang.locale, ...result });
  3508	        } catch (err) {
  3509	          writeResult({ product_id: bulkPid, product: product.title, locale: lang.locale, success: false, error: err.message });
  3510	        }
  3511	        await new Promise(resolve => setTimeout(resolve, 300));
  3512	      }
  3513	    }
  3514	
  3515	    console.log(`[bulk] Duke perpunuar me konkurrence ${BULK_CONCURRENCY} produkte njekohesisht`);
  3516	    await runWithConcurrency(toTranslate, BULK_CONCURRENCY, ({ product, missingLocales }) =>
  3517	      processProductLocales(product, missingLocales)
  3518	    );
  3519	
  3520	    res.write(']}');
  3521	    res.end();
  3522	  } catch (error) {
  3523	    res.status(500).json({ error: error.message });
  3524	  }
  3525	});
  3526	
  3527	// Deduplikimi i webhook-it: Shopify e dergon webhook-un 2-3 here per
  3528	// produkt (create + update i menjehershem + retry nese me vone se 5s).
  3529	// Pa kete Set, çdo thirrje e re = Sonnet i ri = cache WRITE = ~3.5 cent.
  3530	// Me kete: thirrja e dyte per të njejtin shop+product brenda 30s injorohet.
  3531	const recentWebhooks = new Set();
  3532	
  3533	// Product create + update — lokalizon automatikisht
  3534	app.post('/webhook/product-create', requireWebhookHmac, async (req, res) => {
  3535	  res.status(200).send('OK');
  3536	  const rawBody = req.body;
  3537	  const shop = req.headers['x-shopify-shop-domain'];
  3538	  console.log('=== WEBHOOK product-create/update ===', shop);
  3539	  try {
  3540	    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
  3541	    if (!body.title || !body.id) return;
  3542	
  3543	    // Deduplikim: Shop + product_id + 30 sekonda
  3544	    const webhookKey = `${shop}:${body.id}`;
  3545	    if (recentWebhooks.has(webhookKey)) {
  3546	      console.log(`[webhook-dedup] Anashkaluar thirrje e dyfishte per ${webhookKey}`);
  3547	      return;
  3548	    }
  3549	    recentWebhooks.add(webhookKey);
  3550	    setTimeout(() => recentWebhooks.delete(webhookKey), 30000);
  3551	
  3552	    // Kontrollo nese produkti ekziston tashme - perdoret edhe per limit check
  3553	    const { data: existing } = await supabase
  3554	      .from('translations')
  3555	      .select('original_title, original_description')
  3556	      .eq('shop', shop)
  3557	      .eq('product_id', String(body.id))
  3558	      .limit(1);
  3559	
  3560	    const isNewProduct = !existing || existing.length === 0;
  3561	
  3562	    // Plan limit check - vetem per produkte te REJA. Produktet ekzistuese
  3563	    // mund te ri-perkthehen kur editohen (psh title/description ndryshon),
  3564	    // pavaresisht limitit - nuk shton ne numerimin e produkteve.
  3565	    if (isNewProduct) {
  3566	      const PLANS = app.locals.PLANS;
  3567	      if (PLANS) {
  3568	        const { data: storeData } = await supabase
  3569	          .from('stores').select('plan, plan_started_at').eq('shop', shop).single();
  3570	        const planName = storeData?.plan || 'free';
  3571	        const planStartedAt = storeData?.plan_started_at || null;
  3572	        const plan = PLANS[planName] || PLANS.free;
  3573	        const uniqueProducts = await getLocalizedProductCount(shop, planStartedAt);
  3574	        if (uniqueProducts >= plan.product_limit) {
  3575	          console.warn(`[plan-limit] Webhook blocked for ${shop} — ${planName} limit (${plan.product_limit}, used ${uniqueProducts})`);
  3576	          return;
  3577	        }
  3578	      }
  3579	    }
  3580	
  3581	    if (isNewProduct) {
  3582	      // Produkt i ri — lokalizon direkt pa asnjë kontroll
  3583	      console.log(`New product detected: "${body.title}" — triggering localization`);
  3584	    } else {
  3585	      // Produkt ekzistues — lokalizon vetëm nëse titulli OSE description ka ndryshuar
  3586	      const currentDesc = (body.body_html || '').replace(/<[^>]*>/g, '').trim();
  3587	      const savedDesc = (existing[0]?.original_description || '').replace(/<[^>]*>/g, '').trim();
  3588	      const titleChanged = existing[0]?.original_title?.toLowerCase() !== body.title.toLowerCase();
  3589	      const descChanged = currentDesc.length > 0 && savedDesc !== currentDesc;
  3590	
  3591	      if (!titleChanged && !descChanged) {
  3592	        console.log(`Product unchanged: "${body.title}" — skipping`);
  3593	        return;
  3594	      }
  3595	
  3596	      console.log(`Product changed: "${body.title}" — title:${titleChanged} desc:${descChanged} — relocalizing`);
  3597	      await supabase.from('translations').delete()
  3598	        .eq('shop', shop)
  3599	        .eq('product_id', String(body.id));
  3600	    }
  3601	
  3602	    console.log('Calling localizeProduct directly for:', body.title);
  3603	    setImmediate(async () => {
  3604	      try {
  3605	        const store = await getStore(shop);
  3606	        if (!store?.access_token) return;
  3607	        const glossary = store.glossary || 'checkout, Shopify';
  3608	        const savedLocales = store.selected_locales || [];
  3609	        const locales = savedLocales.length > 0
  3610	          ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
  3611	          : await getShopLocales(shop, store.access_token);
  3612	        if (!locales?.length) return;
  3613	        const pid = normalizeProductId(body.id);
  3614	        for (const lang of locales) {
  3615	          try {
  3616	            await localizeProduct(shop, store.access_token, pid, lang.targetLang, lang.locale, store.tone || 'professional', glossary);
  3617	            console.log(`[webhook] Done: ${body.title} → ${lang.locale}`);
  3618	          } catch(e) { console.error(`[webhook] Error ${lang.locale}:`, e.message); }
  3619	          await new Promise(r => setTimeout(r, 300));
  3620	        }
  3621	      } catch(e) { console.error('[webhook] Error:', e.message); }
  3622	    });
  3623	  } catch (err) {
  3624	    console.error('Webhook error:', err.message);
  3625	  }
  3626	});
  3627	
  3628	// Product delete — fshi nga Supabase
  3629	app.post('/webhook/product-delete', async (req, res) => {
  3630	  res.status(200).send('OK');
  3631	  const rawBody = req.body;
  3632	  const shop = req.headers['x-shopify-shop-domain'];
  3633	  try {
  3634	    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
  3635	    if (!body.id) return;
  3636	    console.log('=== WEBHOOK product-delete ===', shop, body.id);
  3637	    await supabase.from('translations').delete()
  3638	      .eq('shop', shop)
  3639	      .eq('product_id', String(body.id));
  3640	    console.log('Deleted translations for product:', body.id);
  3641	  } catch (err) {
  3642	    console.error('Webhook delete error:', err.message);
  3643	  }
  3644	});
  3645	
  3646	// Route bazë per compliance webhooks te regjistruara ne TOML si uri = "/webhook"
  3647	// Shopify dergon te gjitha compliance_topics te kjo URL me X-Shopify-Topic header
  3648	app.post('/webhook', requireWebhookHmac, (req, res) => {
  3649	  const topic = req.headers['x-shopify-topic'] || '';
  3650	  console.log(`[compliance] /webhook received topic: ${topic}`);
  3651	  if (topic === 'shop/redact') {
  3652	    res.status(200).send('OK');
  3653	    const body = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString()) : req.body;
  3654	    const shop = body?.myshopify_domain || req.headers['x-shopify-shop-domain'];
  3655	    if (shop) {
  3656	      supabase.from('translations').delete().eq('shop', shop).then(() =>
  3657	        supabase.from('stores').delete().eq('shop', shop)
  3658	      ).catch(e => console.error('[compliance] shop/redact error:', e.message));
  3659	    }
  3660	  } else {
  3661	    // customers/data_request, customers/redact — Getoify nuk ruan te dhena personale
  3662	    res.status(200).send('OK');
  3663	  }
  3664	});
  3665	
  3666	// ─── COMPLIANCE WEBHOOKS (required for Shopify App Store) ────────────────────
  3667	
  3668	// HMAC verification per te gjitha webhook-et e Shopify — kerkese e detyrueshme
  3669	// per aprovim ne Shopify App Store. Shopify dergon HMAC-SHA256 header
  3670	// 'x-shopify-hmac-sha256' me çdo webhook; nese nuk perputhet me SECRET-in
  3671	// tone, kerkesa refuzohet me 401 (dikush tjeter po perpiqet te dergoje data).
  3672	function verifyShopifyWebhookHmac(req) {
  3673	  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  3674	  if (!hmacHeader) return false;
  3675	  const secret = (process.env.SHOPIFY_API_SECRET || '').trim();
  3676	  if (!secret) return false;
  3677	  const rawBody = req.rawBody || (Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body)));
  3678	  const digest = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  3679	  const digestBuf = Buffer.from(digest);
  3680	  const hmacBuf = Buffer.from(hmacHeader);
  3681	  if (digestBuf.length !== hmacBuf.length) return false;
  3682	  return crypto.timingSafeEqual(digestBuf, hmacBuf);
  3683	}
  3684	
  3685	// Middleware per compliance webhooks — bllokon kerkesa pa HMAC te vlefshme
  3686	function requireWebhookHmac(req, res, next) {
  3687	  if (!verifyShopifyWebhookHmac(req)) {
  3688	    console.warn('[hmac] Webhook HMAC verification failed — request rejected');
  3689	    return res.status(401).send('Unauthorized');
  3690	  }
  3691	  next();
  3692	}
  3693	
  3694	// customers/data_request — merchant asks for customer data export
  3695	app.post('/webhook/customers/data-request', requireWebhookHmac, (req, res) => {
  3696	  // Getoify does not store personal customer data — nothing to export
  3697	  console.log('[compliance] customers/data_request received');
  3698	  res.status(200).send('OK');
  3699	});
  3700	
  3701	// customers/redact — merchant asks to delete customer data
  3702	app.post('/webhook/customers/redact', requireWebhookHmac, (req, res) => {
  3703	  // Getoify does not store personal customer data — nothing to delete
  3704	  console.log('[compliance] customers/redact received');
  3705	  res.status(200).send('OK');
  3706	});
  3707	
  3708	// shop/redact — shop uninstalled, delete all shop data
  3709	app.post('/webhook/shop/redact', requireWebhookHmac, async (req, res) => {
  3710	  res.status(200).send('OK');
  3711	  const rawBody = req.body;
  3712	  try {
  3713	    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
  3714	    const shop = body.myshopify_domain || req.headers['x-shopify-shop-domain'];
  3715	    if (!shop) return;
  3716	    console.log('[compliance] shop/redact — deleting all data for:', shop);
  3717	    await supabase.from('translations').delete().eq('shop', shop);
  3718	    await supabase.from('stores').delete().eq('shop', shop);
  3719	    console.log('[compliance] shop/redact done:', shop);
  3720	  } catch(e) {
  3721	    console.error('[compliance] shop/redact error:', e.message);
  3722	  }
  3723	});
  3724	
  3725	app.post('/process-product', requireShopAuth, async (req, res) => {
  3726	  const shop = req.verifiedShop;
  3727	  const { productId, productTitle } = req.body;
  3728	  let pid;
  3729	  try {
  3730	    pid = normalizeProductId(productId);
  3731	  } catch (e) {
  3732	    return res.status(400).json({ error: e.message });
  3733	  }
  3734	  console.log('process-product called:', { shop, product_id: pid, productTitle });
  3735	  try {
  3736	    const store = await getStore(shop);
  3737	    console.log('store found:', store.shop, 'locales:', store.selected_locales, 'token:', store.access_token ? 'ok' : 'MISSING');
  3738	    const token = store.access_token;
  3739	    if (!token) throw new Error('No access_token in store');
  3740	    const tone = store.tone || 'professional and elegant';
  3741	    const glossary = store.glossary || 'checkout, Shopify';
  3742	    const savedLocales = store.selected_locales || [];
  3743	
  3744	    // Hard plan limit check — COUNT(DISTINCT) via Supabase RPC
  3745	    const PLANS = app.locals.PLANS;
  3746	    if (PLANS) {
  3747	      const planName = store.plan || 'free';
  3748	      const planStartedAt2 = store.plan_started_at || null;
  3749	      const plan = PLANS[planName] || PLANS.free;
  3750	      const uniqueProducts = await getLocalizedProductCount(shop, planStartedAt2);
  3751	      console.warn(`[plan-limit] ${shop} ${planName}: ${uniqueProducts}/${plan.product_limit} products used`);
  3752	      if (uniqueProducts >= plan.product_limit) {
  3753	        console.warn(`[plan-limit] ${shop} hit ${planName} limit (${plan.product_limit}, used ${uniqueProducts})`);
  3754	      await sendNotification(
  3755	        `Limit reached: ${shop} (${planName})`,
  3756	        `<h2>Merchant hit plan limit</h2>
  3757	         <p><b>Store:</b> ${shop}</p>
  3758	         <p><b>Plan:</b> ${planName} (limit: ${plan.product_limit} products)</p>
  3759	         <p><b>Used:</b> ${uniqueProducts} products</p>
  3760	         <p><b>Time:</b> ${new Date().toISOString()}</p>
  3761	         <p>This merchant may be ready to upgrade.</p>`
  3762	      );
  3763	        return res.status(403).json({
  3764	          error: `Plan limit reached. Your ${plan.label} plan supports ${plan.product_limit} products.`,
  3765	          upgrade_url: `${process.env.APP_URL}/pricing`,
  3766	          plan: planName,
  3767	          limit: plan.product_limit
  3768	        });
  3769	      }
  3770	    }
  3771	    console.log('savedLocales:', savedLocales);
  3772	    const locales = savedLocales.length > 0
  3773	      ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
  3774	      : await getShopLocales(shop, token);
  3775	    console.log('locales to process:', locales);
  3776	    if (!locales || locales.length === 0) throw new Error('No locales found for this store');
  3777	    const results = [];
  3778	    for (const lang of locales) {
  3779	      try {
  3780	        await localizeProduct(shop, token, pid, lang.targetLang, lang.locale, tone, glossary);
  3781	        console.log(`Done: ${productTitle} (${pid}) in ${lang.targetLang}`);
  3782	        results.push({ product_id: pid, locale: lang.locale, success: true });
  3783	      } catch (err) {
  3784	        console.error(`Error ${lang.locale}:`, err.message);
  3785	        results.push({ product_id: pid, locale: lang.locale, success: false, error: err.message });
  3786	      }
  3787	      await new Promise(resolve => setTimeout(resolve, 300));
  3788	    }
  3789	    res.json({ success: true, product_id: pid, results });
  3790	  } catch (err) {
  3791	    console.error('Process error:', err.message);
  3792	    res.status(500).json({ error: err.message });
  3793	  }
  3794	});
  3795	
  3796	// Pastrues global, i pavarur, per rreshta 'processing' te ngecur — thirret
  3797	// PARA pollNewProducts(), jo brenda saj. Nuk prek logjiken ekzistuese te
  3798	// pollNewProducts() apo /bulk-localize-all fare — thjesht fshin rreshtat e
  3799	// vjeter 'processing' NE TE GJITHA shops, para se ato dy te lexojne
  3800	// databazen. Pasi rreshti eshte fshire, logjika e TYRE ekzistuese (needsLocalize,
  3801	// missingLocales) e sheh vetvetiu "s'ka rresht" dhe riprovon normalisht —
  3802	// pa pasur nevoje te ndryshohet asnje rresht i filtrimit te tyre.
  3803	async function cleanupStaleProcessingLocks() {
  3804	  const STALE_MS = 3 * 60 * 1000; // 3 min — njesoj si PROCESSING_LOCK_STALE_MS
  3805	  const cutoff = new Date(Date.now() - STALE_MS).toISOString();
  3806	  try {
  3807	    const { data: staleRows, error } = await supabase
  3808	      .from('translations')
  3809	      .delete()
  3810	      .eq('status', 'processing')
  3811	      .lt('created_at', cutoff)
  3812	      .select('shop, product_id, locale');
  3813	    if (error) { console.warn('[cleanup] Fshirja e locks te ngecur deshtoi:', error.message); return; }
  3814	    if (staleRows?.length > 0) {
  3815	      console.log(`[cleanup] Fshiu ${staleRows.length} rresht(a) 'processing' te ngecur (>3 min):`,
  3816	        staleRows.map(r => `${r.shop}/${r.product_id}/${r.locale}`).join(', '));
  3817	    }
  3818	  } catch(e) {
  3819	    console.warn('[cleanup] Gabim:', e.message);
  3820	  }
  3821	}
  3822	
  3823	async function pollNewProducts() {
  3824	  console.log('Polling for new products...');
  3825	  try {
  3826	    const { data: stores } = await supabase.from('stores').select('*');
  3827	    if (!stores || !stores.length) return;
  3828	
  3829	    for (const store of stores) {
  3830	      const token = store.access_token;
  3831	      const shop = store.shop;
  3832	      const tone = store.tone || 'professional and elegant';
  3833	      const glossary = store.glossary || 'checkout, Shopify';
  3834	
  3835	      // Skip stores with old/invalid tokens
  3836	      if (!token || token.startsWith('shpua_')) {
  3837	        console.log('Skipping store with invalid token:', shop);
  3838	        continue;
  3839	      }
  3840	
  3841	      // Plan limit check — skip polling for stores that hit their product limit
  3842	      const PLANS = app.locals.PLANS;
  3843	      let uniqueProducts = 0;
  3844	      let planLimit = 15;
  3845	      if (PLANS) {
  3846	        const planName = store.plan || 'free';
  3847	        const planStartedAt = store.plan_started_at || null;
  3848	        const plan = PLANS[planName] || PLANS.free;
  3849	        planLimit = plan.product_limit;
  3850	        uniqueProducts = await getLocalizedProductCount(shop, planStartedAt);
  3851	        console.warn(`[poll] ${shop} ${planName}: ${uniqueProducts}/${planLimit} products used`);
  3852	        if (uniqueProducts >= planLimit) {
  3853	          console.warn(`[poll] Skipping ${shop} — ${planName} limit reached (${planLimit}, used ${uniqueProducts})`);
  3854	          continue;
  3855	        }
  3856	      }
  3857	
  3858	      try {
  3859	        const res = await axios.get(
  3860	          `https://${shop}/admin/api/2024-01/products.json?limit=50&order=created_at+desc`,
  3861	          { headers: { 'X-Shopify-Access-Token': token } }
  3862	        );
  3863	
  3864	        for (const product of res.data.products) {
  3865	          // Only localize if this product_id has never been translated.
  3866	          // Never delete existing translations automatically — this caused
  3867	          // data corruption where old product descriptions overwrote new ones.
  3868	          const { data } = await supabase
  3869	            .from('translations')
  3870	            .select('id')
  3871	            .eq('shop', shop)
  3872	            .eq('product_id', String(product.id))
  3873	            .limit(1);
  3874	
  3875	          const needsLocalize = !data || data.length === 0;
  3876	
  3877	          if (needsLocalize) {
  3878	
  3879	            // Re-check limit on each new product — stop mid-run if reached
  3880	            if (PLANS && uniqueProducts >= planLimit) {
  3881	              console.log(`[poll] ${shop} reached limit (${planLimit}) mid-run — stopping`);
  3882	              break;
  3883	            }
  3884	
  3885	            console.log('New product found via polling:', product.title);
  3886	            const savedLocales = store.selected_locales || [];
  3887	            const locales = savedLocales.length > 0
  3888	              ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
  3889	              : await getShopLocales(shop, token);
  3890	            for (const lang of locales) {
  3891	              try {
  3892	                await localizeProduct(shop, token, normalizeProductId(product.id), lang.targetLang, lang.locale, tone, glossary);
  3893	                console.log(`Poll done: ${product.title} in ${lang.targetLang}`);
  3894	              } catch(e) {
  3895	                console.error('Poll localize error:', e.message);
  3896	              }
  3897	            }
  3898	            if (PLANS) uniqueProducts++;
  3899	          }
  3900	        }
  3901	      } catch(e) {
  3902	        console.error('Poll store error:', shop, e.message);
  3903	      }
  3904	    }
  3905	  } catch(e) {
  3906	    console.error('Poll error:', e.message);
  3907	  }
  3908	}
  3909	
  3910	// Collection webhook
  3911	app.post('/webhook/collection-create', async (req, res) => {
  3912	  res.status(200).send('OK');
  3913	  const rawBody = req.body;
  3914	  const shop = req.headers['x-shopify-shop-domain'];
  3915	  console.log('=== WEBHOOK collection-create/update ===', shop);
  3916	  try {
  3917	    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
  3918	    if (!body.id) return;
  3919	    const store = await getStore(shop).catch(() => null);
  3920	    if (!store?.access_token) return;
  3921	    const savedLocales = store.selected_locales || [];
  3922	    if (!savedLocales.length) return;
  3923	    const glossary = store.glossary || 'checkout, Shopify';
  3924	    for (const locale of savedLocales) {
  3925	      try {
  3926	        await localizeCollection(shop, store.access_token, body.id, LOCALE_MAP[locale] || locale, locale, glossary);
  3927	        console.log(`[collection webhook] Done: ${body.title || body.id} → ${locale}`);
  3928	      } catch(e) { console.error('[collection webhook] Error:', locale, e.message); }
  3929	      await new Promise(r => setTimeout(r, 300));
  3930	    }
  3931	  } catch(err) { console.error('[collection webhook] Error:', err.message); }
  3932	});
  3933	
  3934	// Vercel Cron endpoint — called every 5 minutes by vercel.json crons config
  3935	// setInterval does not work on Vercel serverless — use this instead
  3936	app.get('/poll', async (req, res) => {
  3937	  await cleanupStaleProcessingLocks();
  3938	  await pollNewProducts();
  3939	  res.json({ ok: true, time: new Date().toISOString() });
  3940	});
  3941	
  3942	// Keep setInterval only for local development
  3943	if (process.env.NODE_ENV !== 'production') {
  3944	  setInterval(pollNewProducts, 5 * 60 * 1000);
  3945	  setTimeout(pollNewProducts, 15000);
  3946	}
  3947	
  3948	async function autoResetWebhooks() {
  3949	  try {
  3950	    const { data: stores } = await supabase.from('stores').select('shop, access_token');
  3951	    if (!stores?.length) return;
  3952	    const webhookTopics = [
  3953	      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
  3954	      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
  3955	      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` },
  3956	      { topic: 'collections/create', address: `${APP_URL}/webhook/collection-create` },
  3957	      { topic: 'collections/update', address: `${APP_URL}/webhook/collection-create` }
  3958	    ];
  3959	    for (const store of stores) {
  3960	      if (!store.access_token || store.access_token.startsWith('shpua_')) continue;
  3961	      try {
  3962	        const listRes = await axios.get(`https://${store.shop}/admin/api/2024-01/webhooks.json`,
  3963	          { headers: { 'X-Shopify-Access-Token': store.access_token }, timeout: 10000 });
  3964	        const existing = listRes.data.webhooks || [];
  3965	        const allCorrect = webhookTopics.every(wh => existing.some(e => e.topic === wh.topic && e.address === wh.address));
  3966	        if (allCorrect) { console.log(`[auto-webhooks] OK: ${store.shop}`); continue; }
  3967	        for (const wh of existing) {
  3968	          await axios.delete(`https://${store.shop}/admin/api/2024-01/webhooks/${wh.id}.json`,
  3969	            { headers: { 'X-Shopify-Access-Token': store.access_token }, timeout: 10000 });
  3970	        }
  3971	        for (const wh of webhookTopics) {
  3972	          await axios.post(`https://${store.shop}/admin/api/2024-01/webhooks.json`,
  3973	            { webhook: { topic: wh.topic, address: wh.address, format: 'json' } },
  3974	            { headers: { 'X-Shopify-Access-Token': store.access_token, 'Content-Type': 'application/json' }, timeout: 10000 });
  3975	        }
  3976	        console.log(`[auto-webhooks] Reset OK: ${store.shop}`);
  3977	      } catch(e) { console.warn(`[auto-webhooks] Failed for ${store.shop}:`, e.message); }
  3978	    }
  3979	  } catch(e) { console.error('[auto-webhooks] Error:', e.message); }
  3980	}
  3981	
  3982	// TEST ENDPOINT — remove after testing
  3983	app.post('/test-prompt', async (req, res) => {
  3984	  const { title, lang, shop } = req.body;
  3985	
  3986	  // Kontroll limiti edhe per test-prompt — kjo ishte rruga e vetme e mbetur
  3987	  // e pabllokuar. Pa shop, nuk mund te kontrollojme; nese shop eshte dhene,
  3988	  // bllokohet si cdo rruge tjeter.
  3989	  if (shop && app.locals.PLANS) {
  3990	    try {
  3991	      const store = await getStore(shop);
  3992	      if (store) {
  3993	        const planName = store.plan || 'free';
  3994	        const plan = app.locals.PLANS[planName] || app.locals.PLANS.free;
  3995	        const planStartedAt = store.plan_started_at || null;
  3996	        let q = supabase.from('translations').select('product_id').eq('shop', shop).limit(10000);
  3997	        if (planStartedAt) q = q.gte('created_at', planStartedAt);
  3998	        const { data: rows } = await q;
  3999	        const uniqueCount = new Set((rows || []).map(r => String(r.product_id))).size;
  4000	        if (uniqueCount >= plan.product_limit) {
  4001	          return res.status(403).json({
  4002	            error: `Plan limit reached (${uniqueCount}/${plan.product_limit}). Upgrade to continue.`,
  4003	            limit: plan.product_limit,
  4004	            used: uniqueCount
  4005	          });
  4006	        }
  4007	      }
  4008	    } catch(limitErr) {
  4009	      if (limitErr.message?.startsWith('PLAN_LIMIT')) {
  4010	        return res.status(403).json({ error: limitErr.message });
  4011	      }
  4012	      console.warn('[test-prompt] limit check failed:', limitErr.message);
  4013	    }
  4014	  }
  4015	
  4016	  const product = { title, product_type: '', tags: '', body_html: '' };
  4017	  try {
  4018	    const result = await generateProductCopy(product, lang, 'checkout, Shopify', '', null, [], shop);
  4019	    res.json(result);
  4020	  } catch(e) {
  4021	    if (e.message?.startsWith('PLAN_LIMIT')) {
  4022	      return res.status(403).json({ error: e.message });
  4023	    }
  4024	    res.status(500).json({ error: e.message });
  4025	  }
  4026	});
  4027	
  4028	const PORT = process.env.PORT || 3000;
  4029	app.listen(PORT, async () => {
  4030	  console.log(`Getoify server running on port ${PORT}`);
  4031	  setTimeout(autoResetWebhooks, 5000);
  4032	});