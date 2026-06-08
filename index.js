const express = require('express');
const dotenv = require('dotenv');
const axios = require('axios');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

dotenv.config({ override: false });

const app = express();

app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const { 
  SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_SCOPES, 
  APP_URL, SUPABASE_URL, SUPABASE_SERVICE_KEY
} = process.env;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Intercept Shopify 401 — mark token invalid in Supabase
axios.interceptors.response.use(
  res => res,
  async err => {
    const url = err.config?.url || '';
    const status = err.response?.status;
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
const registerStripe = require('./lib/stripe');
registerStripe(app, { supabase });
const registerShopifyBilling = require('./lib/shopify-billing');
registerShopifyBilling(app, { supabase });

const SHOPIFY_PRODUCTS_PAGE = 250;
const SHOPIFY_PRODUCTS_TIMEOUT_MS = 60000;

const LOCALE_MAP = {
  'fr': 'French', 'de': 'German', 'it': 'Italian', 'es': 'Spanish',
  'nl': 'Dutch', 'pt': 'Portuguese', 'pl': 'Polish', 'sv': 'Swedish',
  'da': 'Danish', 'fi': 'Finnish', 'nb': 'Norwegian', 'ja': 'Japanese',
  'zh': 'Chinese', 'ar': 'Arabic', 'hi': 'Hindi', 'id': 'Indonesian',
  'en': 'English'
};

// Static pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/tone', (req, res) => res.sendFile(path.join(__dirname, 'public', 'tone.html')));
app.get('/glossary', (req, res) => res.sendFile(path.join(__dirname, 'public', 'glossary.html')));
app.get('/products-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'products.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'public', 'settings.html')));
app.get('/autosync', (req, res) => res.sendFile(path.join(__dirname, 'public', 'autosync.html')));
app.get('/product', (req, res) => res.sendFile(path.join(__dirname, 'public', 'product-detail.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
app.get('/google6e865cb2268111cc.html', (req, res) => res.send('google-site-verification: google6e865cb2268111cc.html'));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('/shopify-translation-app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'shopify-translation-app.html')));
app.get('/vs/langify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vs', 'langify.html')));

app.get('/product-translations', async (req, res) => {
  const { shop, productId } = req.query;
  if (!shop || !productId) return res.status(400).json({ error: 'Missing shop or productId' });
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
app.get('/token-status', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  const { data } = await supabase.from('stores').select('token_invalid').eq('shop', shop).single();
  res.json({ invalid: data?.token_invalid === true });
});

// OAuth
app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send('Missing shop parameter');
  const redirectUri = `${APP_URL}/auth/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SHOPIFY_SCOPES}&redirect_uri=${redirectUri}`;
  res.redirect(installUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code } = req.query;
  try {
    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: SHOPIFY_API_KEY,
      client_secret: SHOPIFY_API_SECRET,
      code
    });
    const accessToken = response.data.access_token;
    await supabase.from('stores').upsert({ shop, access_token: accessToken, token_invalid: false }, { onConflict: 'shop' });
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
          `https://${shop}/admin/api/2024-01/webhooks.json`,
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

    res.redirect('/dashboard?shop=' + shop + '&token=' + accessToken + '&autorun=1');
  } catch (error) {
    console.error('OAuth callback error:', error.message);
    res.redirect('/?error=oauth_failed&shop=' + (req.query.shop || ''));
  }
});

// Endpoint per te regjistruar webhooks per stores ekzistuese
// Thirre nje here: https://getoify.com/register-webhooks?shop=xxx.myshopify.com
app.get('/register-webhooks', async (req, res) => {
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
          `https://${shop}/admin/api/2024-01/webhooks.json`,
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
app.get('/reset-webhooks', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  try {
    const { data: store } = await supabase.from('stores').select('access_token').eq('shop', shop).single();
    if (!store?.access_token) return res.status(404).json({ error: 'Store not found or no token' });
    const token = store.access_token;

    // Merr te gjitha webhooks ekzistuese
    const listRes = await axios.get(
      `https://${shop}/admin/api/2024-01/webhooks.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const existing = listRes.data.webhooks || [];

    // Fshi te gjitha
    const deleted = [];
    for (const wh of existing) {
      await axios.delete(
        `https://${shop}/admin/api/2024-01/webhooks/${wh.id}.json`,
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      deleted.push({ id: wh.id, topic: wh.topic, address: wh.address });
    }

    // Regjistro sersish me URL te sakte
    const webhookTopics = [
      { topic: 'products/create', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/update', address: `${APP_URL}/webhook/product-create` },
      { topic: 'products/delete', address: `${APP_URL}/webhook/product-delete` }
    ];
    const registered = [];
    for (const wh of webhookTopics) {
      const r = await axios.post(
        `https://${shop}/admin/api/2024-01/webhooks.json`,
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

// API routes
app.get('/locales', async (req, res) => {
  const { shop, token } = req.query;
  if (!shop || !token) return res.status(400).json({ error: 'Missing shop or token' });
  try {
    const query = `query { shopLocales { locale name primary published } }`;
    const response = await axios.post(
      `https://${shop}/admin/api/2024-01/graphql.json`,
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

app.get('/products', async (req, res) => {
  const { shop, token } = req.query;
  if (!shop || !token) return res.status(400).json({ error: 'Missing shop or token' });
  try {
    let allProducts = [];
    let url = `https://${shop}/admin/api/2024-01/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;

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

app.get('/status', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
    // Count only products translated after plan started
    const relevantTranslations = planStartedAt
      ? translations.filter(t => new Date(t.created_at) >= new Date(planStartedAt))
      : translations;
    const uniqueProducts = new Set(relevantTranslations.map(t => t.product_id)).size;
    const allUniqueProducts = new Set(translations.map(t => t.product_id)).size;
    res.json({ total: allUniqueProducts, period_used: uniqueProducts, total_records: translations.length, plan_limit: plan.product_limit, translations });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/store-settings', async (req, res) => {
  const { shop } = req.query;
  try {
    const { data, error } = await supabase
      .from('stores')
      .select('tone, glossary, selected_locales, plan, access_token')
      .eq('shop', shop)
      .single();
    if (error) throw error;
    res.json(data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/settings', async (req, res) => {
  const { shop, tone, glossary } = req.body;
  try {
    const { error } = await supabase.from('stores').update({ tone, glossary }).eq('shop', shop);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/save-locales', async (req, res) => {
  const { shop, selected_locales } = req.body;
  if (!shop || !selected_locales) return res.status(400).json({ error: 'Missing data' });
  try {
    const { error } = await supabase
      .from('stores')
      .update({ selected_locales })
      .eq('shop', shop);
    if (error) throw error;
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

async function getStore(shop) {
  const { data, error } = await supabase.from('stores').select('*').eq('shop', shop).single();
  if (error) throw new Error('Store not found: ' + shop);
  return data;
}

async function getShopLocales(shop, token) {
  const query = `query { shopLocales { locale name primary published } }`;
  const res = await axios.post(
    `https://${shop}/admin/api/2024-01/graphql.json`,
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
    `https://${shop}/admin/api/2024-01/graphql.json`,
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
    `https://${shop}/admin/api/2024-01/products/${pid}.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  if (!productBodyIsEmpty(checkRes.data.product?.body_html)) return false;

  await axios.put(
    `https://${shop}/admin/api/2024-01/products/${pid}.json`,
    { product: { body_html: formatBodyHtml(descriptionText) } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  console.log('Updated Shopify product body_html:', pid);
  return true;
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
  // Other major
  'ikea', 'lego', 'stanley', 'yeti', 'hydroflask'
];

function titleHasKnownBrand(title) {
  const t = (title || '').toLowerCase();
  return KNOWN_BRANDS.some(brand => t.includes(brand));
}

// Haiku per gjithcka — me i lire, CATEGORY KNOWLEDGE e mbulon te gjitha rastet
function selectModel(hasImage, cleanBody, productTitle) {
  return 'claude-haiku-4-5-20251001';
}

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

async function generateProductCopyWithClaude(product, targetLang, glossary, cleanBody, imageUrl) {
  const category = product.product_type || '';
  const tags = (product.tags || '').split(',').slice(0, 5).join(', ');
  const hasImage = !!imageUrl;
  const model = selectModel(hasImage, cleanBody, product.title);
  const homeKitchen = isHomeKitchenProduct(product);
  const beautyHealth = !homeKitchen && isBeautyHealthProduct(product);

  console.log(`[category] homeKitchen:${homeKitchen} beautyHealth:${beautyHealth} product:"${product.title}"`);

  console.log(`[model-select] ${model} — image:${hasImage} body:${!!cleanBody} product:"${product.title}"`);

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
      avoidWords: 'robust, solide, hochwertig, effizient, funktional',
      avoidNote: 'Avoid repeating "robust" or "hochwertig" — use "langlebig", "verarbeitet", "gefertigt" instead',
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
- Translate the product name naturally into ${targetLang}
- Add key specs (capacity, material, size) ONLY if confirmed from the product name or image — never invent
- Format: [Translated name] [Premium if strongly justified] — [spec1] | [spec2]
- Elegant and informative — no ALL CAPS, no exclamation marks
- Max 70 chars

DESCRIPTION RULES:
- Write 1-2 opening sentences MAX — keep them SHORT and grounded. Lead with the product's main benefit or key spec, not with poetry.
- Sensory/emotional words are allowed ONLY if they add real meaning. FORBIDDEN: "nuage", "honore", "incontournable", "rituel", "magie", "transforme" — these are empty metaphors.
- Preferred words for ${targetLang}: ${langCfg.sensoryWords}
- AVOID: ${langCfg.avoidWords}
- ${langCfg.avoidNote}
- Address the customer using "${langCfg.tone}"
- Then write exactly 4 bullet points starting with ✓, in this order:
  ${langCfg.bulletOrder}
- Each bullet MUST contain a number, measurement, or confirmed technical fact. Poetry bullets are FORBIDDEN.
- RATIO: 80% technical facts, 20% tone. Not the reverse.
- Total description max 120 words

CATEGORY KNOWLEDGE RULE:
You are an ecommerce expert with deep product knowledge across all categories. Apply this logic:

STEP A — KNOWN BRAND + MODEL (MANDATORY SPECS):
If you recognize the exact product (Samsung Galaxy S25 Ultra, iPhone 16 Pro Max, Sony WF-1000XM6, Apple AirPods Pro, Dyson V15, Nespresso Vertuo, Nike Air Max 270, etc.):

MANDATORY:
→ At least 3 bullets must contain a specific confirmed number or spec name.
→ Generic phrases are STRICTLY FORBIDDEN — these are marketing words, not specs: "advanced processor", "powerful chip", "high resolution", "long battery life", "imagerie IA avancée", "traitement avancé", "exigeantes et créatives", "tâches complexes", "performances optimisées", "s'adapte à votre", "s'ajuste à votre", "compiti impegnativi", "intelligent features", "stunning display", "incredible camera", "next-generation", "optimisées pour", "précision intentionnelle", "double action", "à double action", "formule innovante", "technologie avancée", "soin intensif". If you catch yourself writing any of these, replace with the real ingredient, number, or spec name.
→ Write the REAL name: "Snapdragon 8 Elite" not "advanced chip". "A18 Pro 3nm" not "powerful processor".
→ ONE spec per bullet — never combine. WRONG: "✓ A18 Pro gère les tâches exigeantes et créatives". RIGHT: "✓ Puce A18 Pro 3nm — Neural Engine 16 cœurs".
→ If you know 2 numbers for the same spec (e.g. battery + charge speed), they count as ONE bullet: "✓ 5000mAh — charge 45W filaire en 70 min".
→ UNCERTAINTY RULE — CRITICAL: If you are not 100% certain of a specific number (chip generation, exact MP count, exact mAh), do NOT invent it. Instead use "up to" framing or omit the uncertain number. WRONG: "✓ Puce A19 Pro" (A19 doesn't exist). RIGHT: "✓ Puce A17 Pro 3nm" (confirmed). If unsure whether it's A17 or A18, write "Puce Apple Pro 3nm" without the generation number. A fabricated spec is worse than a missing one — merchants will publish it as fact.

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

RULE: "up to" = typical range (Step B). Real confirmed numbers = Step A only. Never mix.

${homeKitchen ? `
HOME & KITCHEN SPECIFIC RULES:
This is a kitchen/home appliance product. Apply these additional rules:
- PRIORITY SPECS: motor power (W), capacity (L or ml), speed settings (number), included accessories
- If brand+model is known (KitchenAid 5KSM175PS, Dyson V15, Nespresso Vertuo): list ALL confirmed specs — W, L, speeds, accessories
- Bullet ✓1: capacity + material (e.g. "Bol inox 4,8 L — compatible lave-vaisselle")
- Bullet ✓2: motor/mechanism with W and speed (e.g. "Moteur 300W — 10 vitesses, mélange planétaire")
- Bullet ✓3: accessories included (e.g. "Fouet, batteur plat et crochet pétrin inclus")
- Bullet ✓4: care + warranty confirmed facts only
- PROSE: use "plaisir", "savoir-faire", "art", "précision" — NEVER "chaleur" for appliances (chaleur = physical heat, wrong context)
- Do NOT use "chaleur" for mixers, blenders, or any appliance that does not produce heat
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
- Bullet ✓1: format + usage duration (e.g. "Flacon 473ml — jusqu'à 3 mois d'utilisation quotidienne")
- Bullet ✓2: key active ingredients + technology (e.g. "3 Céramides essentiels + Technologie MVE — hydratation 24h")
- Bullet ✓3: skin type + dermatologist claim (e.g. "Testé dermatologiquement — peaux sensibles et normales")
- Bullet ✓4: texture/format + confirmed care (e.g. "Formule sans parfum, non-comédogène — sans rinçage")

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
- Main keyword first
- Include one key spec if it fits
- No punctuation at the end

META DESCRIPTION RULES (exactly 140-160 chars — use the full space):
- Start with an action verb in ${targetLang}
- One specific concrete benefit
${langCfg.cta ? `- End with: "${langCfg.cta}"` : '- No call to action'}

SELF-CHECK — do this mentally before writing any JSON:

Step 1 — SPECS CHECK:
- Bullet ✓1 must contain a number or measurement (ml, cm, kg, pieces, hours...)
- If no measurement is known from the name or image, replace bullet ✓1 with a confirmed functional detail instead
- NEVER write vague bullets like "✓ Generous capacity" or "✓ Quality construction"

Step 2 — REDUNDANCY CHECK:
- List every key noun and adjective you plan to use
- If any word repeats across title + prose + bullets + meta → replace the duplicate with a synonym
- Any material name: max 1 occurrence total across the entire output
- "quality" or its translation in ${targetLang}: max 1 occurrence total
- "design": max 1 occurrence total

Step 3 — BULLET CHECK:
- Bullet ✓1: spec with number/measurement — if unknown, use the most specific confirmed functional detail
- Bullet ✓2: how the mechanism works (one concrete action)
- Bullet ✓3: design or emotional appeal (style, origin, feel) — no repeated adjectives from prose
- Bullet ✓4: care or warranty — write in ${targetLang} only. If dishwasher-safe is NOT confirmed, write a storage or warranty fact instead. NEVER invent care instructions.
- Each bullet max 12 words

Step 4 — TONE CHECK:
- Every verb addressed to the customer must use "${langCfg.tone}" consistently — no mixing of formal/informal

Only after passing all 4 steps, write the JSON.

Respond ONLY in this exact JSON format, no extra text, no markdown backticks:
{"title":"...","description":"...","meta_title":"...","meta_description":"..."}`;

  if (hasImage && !cleanBody) {
    // Sonnet 4.6 — imazh + titull, gjeneron nga zero
    const titleSection = product.title
      ? `Product name: "${product.title}"\n${category ? `Category: ${category}\n` : ''}${tags ? `Tags: ${tags}\n` : ''}`
      : `No product name provided. Identify the product from the image and write an appropriate name in ${targetLang}.`;

    const textPrompt = `You are a native ${targetLang} speaker and professional ecommerce copywriter. Analyze the product image carefully.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${titleSection}

Look carefully at the image. Identify ONLY what is clearly visible: materials, colors, shape, dimensions, text/branding, use case.
Do NOT invent specifications that are not visible or stated.

${sharedRules}`;

    userContent = [
      { type: 'image', source: { type: 'url', url: imageUrl } },
      { type: 'text', text: textPrompt }
    ];
  } else {
    // Haiku — tekst i paster (perkthim ose gjerim nga titulli)
    const textPrompt = `You are a native ${targetLang} speaker and professional ecommerce copywriter.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${cleanBody
      ? `The merchant has written this product description. Translate it faithfully into ${targetLang}.
Do NOT rewrite, do NOT add information, do NOT change the structure or style.
Preserve bullet points, formatting, and tone exactly.

TITLE: ${product.title}
DESCRIPTION: ${cleanBody}

TRANSLATION RULES:
- Translate the title naturally into ${targetLang}
- If the original has bullets keep bullets, if prose keep prose
- Apply the tone "${langCfg.tone}" consistently throughout
- Use sensory words where natural: ${langCfg.sensoryWords}
- Avoid: ${langCfg.avoidWords}

${sharedRules}`
      : `Product name: "${product.title}"
${category ? `Category: ${category}` : ''}
${tags ? `Tags: ${tags}` : ''}

No description exists. Write product copy in ${targetLang} based ONLY on the product name above — no invention.

${sharedRules}`
    }`;

    userContent = textPrompt;
  }

  try {
    const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model,
      max_tokens: 1500,
      messages: [{ role: 'user', content: userContent }]
    }, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      timeout: 45000
    });

    let rawText = '';
    for (const block of claudeRes.data.content) {
      if (block.type === 'text') rawText += block.text;
    }
    rawText = rawText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in Claude response');
    const parsed = JSON.parse(jsonMatch[0]);
    if (!parsed.title || !parsed.description) throw new Error('Missing title or description');
    return parsed;
  } catch (claudeErr) {
    console.error('Claude API failed:', claudeErr.response?.data || claudeErr.message);
    return {
      title: product.title,
      description: product.title,
      meta_title: product.title.substring(0, 60),
      meta_description: product.title.substring(0, 160)
    };
  }
}

async function localizeProduct(shop, token, productId, targetLang, locale, tone, glossary) {
  const pid = normalizeProductId(productId);
  const productRes = await axios.get(
    `https://${shop}/admin/api/2024-01/products/${pid}.json`,
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
    `https://${shop}/admin/api/2024-01/graphql.json`,
    { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${pid}` } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const contents = digestRes.data.data.translatableResource.translatableContent;
  const digests = {};
  contents.forEach(c => { digests[c.key] = c.digest; });

  const cleanBody = (product.body_html || '').replace(/<[^>]*>/g, '').trim();
  const hadNoDescription = !cleanBody;

  // Nxjerr URL-in e imazhit te pare (nese ekziston) — perdoret per Sonnet 4.6
  const imageUrl = product.images && product.images.length > 0
    ? product.images[0].src
    : null;
  if (imageUrl && !cleanBody) {
    console.log(`[image] "${product.title}" has image + no body — routing to Sonnet 4.6`);
  }

  let translated = await generateProductCopyWithClaude(product, targetLang, glossary, cleanBody, imageUrl);

  if (!translated.meta_title) {
    translated.meta_title = (translated.title || product.title).substring(0, 60);
  }
  if (!translated.meta_description) {
    translated.meta_description = (translated.description || translated.title || product.title).substring(0, 160);
  }

  if (hadNoDescription) {
    try {
      const primaryLocale = await getPrimaryLocale(shop, token);
      const localeKey = locale.split('-')[0];
      const primaryKey = primaryLocale.split('-')[0];
      let bodyForShopify = translated.description;
      if (localeKey !== primaryKey) {
        const primaryLang = LOCALE_MAP[primaryKey] || primaryLocale;
        const primaryCopy = await generateProductCopyWithClaude(product, primaryLang, glossary, '', imageUrl);
        bodyForShopify = primaryCopy.description;
      }
      const bodyUpdated = await updateShopifyProductBodyIfEmpty(shop, token, pid, bodyForShopify);
      if (bodyUpdated) {
        // Re-fetch digests so body_html digest is available for translation registration
        const freshDigestRes = await axios.post(
          `https://${shop}/admin/api/2024-01/graphql.json`,
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
  const pushRes = await axios.post(
    `https://${shop}/admin/api/2024-01/graphql.json`,
    {
      query: mutation,
      variables: {
        resourceId: `gid://shopify/Product/${pid}`,
        translations: [
          { key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] },
          ...(digests['body_html']
            ? [{ key: 'body_html', value: translated.description, locale, translatableContentDigest: digests['body_html'] }]
            : []),
          // meta_title: use its own digest if exists, otherwise use title digest as fallback
          ...(translated.meta_title ? [{ key: 'meta_title', value: translated.meta_title, locale, translatableContentDigest: digests['meta_title'] || digests['title'] }] : []),
          // meta_description: use its own digest if exists, otherwise use body_html digest as fallback
          ...(translated.meta_description ? [{ key: 'meta_description', value: translated.meta_description, locale, translatableContentDigest: digests['meta_description'] || digests['body_html'] || digests['title'] }] : [])
        ]
      }
    },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );

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

  // Log Shopify response për debugging
  const shopifyResult = pushRes.data.data?.translationsRegister;
  if (shopifyResult?.userErrors?.length > 0) {
    console.error('Shopify userErrors:', JSON.stringify(shopifyResult.userErrors));
  } else {
    console.log('Shopify translations pushed OK:', shopifyResult?.translations?.length, 'fields');
  }

  console.log('Saved translation:', { shop, product_id: pid, locale, title: product.title });

  return { product_id: pid, product: product.title, translated, shopify: shopifyResult };
}

app.post('/localize', async (req, res) => {
  const { shop, token, productId, targetLang, locale, tone, glossary } = req.body;
  try {
    const pid = normalizeProductId(productId);
    const result = await localizeProduct(shop, token, pid, targetLang, locale, tone, glossary);
    res.json({ success: true, product_id: pid, ...result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/bulk-localize-all', async (req, res) => {
  const { shop, token, tone, glossary } = req.body;
  try {
    const store = await getStore(shop);
    const savedLocales = store.selected_locales || [];

    // Hard plan limit — slice products to plan maximum
    const PLANS = app.locals.PLANS;
    let productLimit = 15; // free default
    let localeLimit = 2;
    if (PLANS) {
      const planName = store.plan || 'free';
      const plan = PLANS[planName] || PLANS.free;
      productLimit = plan.product_limit;
      localeLimit = plan.locale_limit;
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
    let bulkUrl = `https://${shop}/admin/api/2024-01/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;
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

    // Enforce product limit — never translate more than plan allows
    if (products.length > productLimit) {
      console.warn(`[plan-limit] Slicing ${products.length} → ${productLimit} products for ${shop}`);
      products = products.slice(0, productLimit);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"results":[');
    let first = true;

    for (const product of products) {
      const bulkPid = normalizeProductId(product.id);
      for (const lang of locales) {
        try {
          const result = await localizeProduct(shop, token, bulkPid, lang.targetLang, lang.locale, tone, glossary);
          if (!first) res.write(',');
          res.write(JSON.stringify({ success: true, product_id: bulkPid, locale: lang.locale, ...result }));
          first = false;
        } catch (err) {
          if (!first) res.write(',');
          res.write(JSON.stringify({ product_id: bulkPid, product: product.title, locale: lang.locale, success: false, error: err.message }));
          first = false;
        }
        await new Promise(resolve => setTimeout(resolve, 300));
      }
    }

    res.write(']}');
    res.end();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Product create + update — lokalizon automatikisht
app.post('/webhook/product-create', async (req, res) => {
  res.status(200).send('OK');
  const rawBody = req.body;
  const shop = req.headers['x-shopify-shop-domain'];
  console.log('=== WEBHOOK product-create/update ===', shop);
  try {
    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
    if (!body.title || !body.id) return;

    // Plan limit check before processing
    const PLANS = app.locals.PLANS;
    if (PLANS) {
      const { data: storeData } = await supabase
        .from('stores').select('plan, plan_started_at').eq('shop', shop).single();
      const planName = storeData?.plan || 'free';
      const planStartedAt = storeData?.plan_started_at || null;
      const plan = PLANS[planName] || PLANS.free;
      let productQuery = supabase.from('translations').select('product_id, created_at').eq('shop', shop);
      if (planStartedAt) productQuery = productQuery.gte('created_at', planStartedAt);
      const { data: productRows } = await productQuery;
      const uniqueProducts = new Set((productRows || []).map(r => r.product_id)).size;
      if (uniqueProducts >= plan.product_limit) {
        console.warn(`[plan-limit] Webhook blocked for ${shop} — ${planName} limit (${plan.product_limit} products, ${uniqueProducts} used)`);
        return;
      }
    }

    // Kontrollo nëse produkti ekziston tashmë në translations
    const { data: existing } = await supabase
      .from('translations')
      .select('original_title, original_description')
      .eq('shop', shop)
      .eq('product_id', String(body.id))
      .limit(1);

    const isNewProduct = !existing || existing.length === 0;

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

    console.log('Calling process-product for:', body.title);
    axios.post(`${APP_URL}/process-product`, {
      shop, productId: normalizeProductId(body.id), productTitle: body.title
    }, { timeout: 5000 }).catch(err => console.error('Trigger error:', err.message));
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

app.post('/process-product', async (req, res) => {
  const { shop, productId, productTitle } = req.body;
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

    // Hard plan limit check — count translated products for this shop
    const PLANS = app.locals.PLANS;
    if (PLANS) {
      const planName = store.plan || 'free';
      const planStartedAt2 = store.plan_started_at || null;
      const plan = PLANS[planName] || PLANS.free;
      let productQuery2 = supabase.from('translations').select('product_id, created_at').eq('shop', shop);
      if (planStartedAt2) productQuery2 = productQuery2.gte('created_at', planStartedAt2);
      const { data: productRows2 } = await productQuery2;
      const uniqueProducts = new Set((productRows2 || []).map(r => r.product_id)).size;
      if (uniqueProducts >= plan.product_limit) {
        console.warn(`[plan-limit] ${shop} hit ${planName} limit (${plan.product_limit} products, ${uniqueProducts} used)`);
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

      try {
        const res = await axios.get(
          `https://${shop}/admin/api/2024-01/products.json?limit=50&order=created_at+desc`,
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

// Vercel Cron endpoint — called every 5 minutes by vercel.json crons config
// setInterval does not work on Vercel serverless — use this instead
app.get('/poll', async (req, res) => {
  await pollNewProducts();
  res.json({ ok: true, time: new Date().toISOString() });
});

// Keep setInterval only for local development
if (process.env.NODE_ENV !== 'production') {
  setInterval(pollNewProducts, 5 * 60 * 1000);
  setTimeout(pollNewProducts, 15000);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Getoify server running on port ${PORT}`);
});