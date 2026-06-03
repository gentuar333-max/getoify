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
    res.redirect('/dashboard?shop=' + shop + '&token=' + accessToken + '&autorun=1');
  } catch (error) {
    console.error('OAuth callback error:', error.message);
    res.redirect('/?error=oauth_failed&shop=' + (req.query.shop || ''));
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
    res.json({ total: translations.length, translations });
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

async function generateProductCopyWithClaude(product, targetLang, glossary, cleanBody) {
  const category = product.product_type || '';
  const tags = (product.tags || '').split(',').slice(0, 5).join(', ');

  const prompt = `You are a native ${targetLang} speaker and ecommerce expert.

Glossary (never translate these terms, keep them exactly as written): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${cleanBody
    ? `The merchant has written this product description. Translate it faithfully into ${targetLang}.
Do NOT rewrite, do NOT add new information, do NOT change the style.
Just translate accurately, preserving the original meaning and tone.

TITLE: ${product.title}
DESCRIPTION: ${cleanBody}`
    : `Product name: "${product.title}"
${category ? `Category: ${category}` : ''}
${tags ? `Tags: ${tags}` : ''}

This product has no description. Based ONLY on the product name above, write a 2-sentence description in ${targetLang}.

RULES:
- Use the actual product name — do NOT use placeholder phrases like "ce produit" or "this product"
- Write as if describing this specific product to a friend
- Focus on what it does, how it feels, or why someone would want it
- Max 40 words, no bullet points, no generic adjectives
- Also translate the title naturally into ${targetLang}
- NEVER say the product doesn't exist — all product names are valid
- The title may be in any language — always translate it naturally into ${targetLang}`
  }

Rules for meta_title (max 60 chars):
- Main keyword first
- Natural language, no keyword stuffing

Rules for meta_description (max 160 chars):
- Start with action verb in ${targetLang}
- One specific concrete benefit
- Sound like a human wrote it

Respond ONLY in this exact JSON format, no extra text, no markdown backticks:
{"title":"...","description":"...","meta_title":"...","meta_description":"..."}`;

  try {
    const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: {
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      timeout: 30000
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

  let translated = await generateProductCopyWithClaude(product, targetLang, glossary, cleanBody);

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
        const primaryCopy = await generateProductCopyWithClaude(product, primaryLang, glossary, '');
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

    // Plan limit check
    const checkPlanLimit = app.locals.checkPlanLimit;
    if (checkPlanLimit) {
      const limitCheck = await checkPlanLimit(shop, 99999, savedLocales.length);
      if (!limitCheck.allowed) {
        return res.status(403).json({ error: limitCheck.reason, upgrade_url: limitCheck.upgrade_url, plan: limitCheck.plan });
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

    // Kontrollo nëse titulli ka ndryshuar (product update)
    const { data: existing } = await supabase
      .from('translations')
      .select('original_title')
      .eq('shop', shop)
      .eq('product_id', String(body.id))
      .limit(1);

    const titleChanged = existing && existing.length > 0 &&
      existing[0].original_title?.toLowerCase() !== body.title.toLowerCase();

    if (titleChanged) {
      // Titulli ndryshoi — fshi translations e vjetra dhe rilokalizoje
      console.log(`Title changed: "${existing[0].original_title}" → "${body.title}", relocalizing...`);
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