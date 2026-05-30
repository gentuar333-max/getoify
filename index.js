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

const LOCALE_MAP = {
  'fr': 'French', 'de': 'German', 'it': 'Italian', 'es': 'Spanish',
  'nl': 'Dutch', 'pt': 'Portuguese', 'pl': 'Polish', 'sv': 'Swedish',
  'da': 'Danish', 'fi': 'Finnish', 'nb': 'Norwegian', 'ja': 'Japanese',
  'zh': 'Chinese', 'ar': 'Arabic', 'hi': 'Hindi', 'id': 'Indonesian'
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
  try {
    const { data, error } = await supabase
      .from('translations')
      .select('locale, status, translated_title, translated_description, meta_title, meta_description, original_title, product_handle, created_at')
      .eq('shop', shop)
      .eq('product_id', productId);
    if (error) throw error;
    res.json({ translations: data });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
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
    await supabase.from('stores').upsert({ shop, access_token: accessToken }, { onConflict: 'shop' });
    console.log('Store connected:', shop);
    res.redirect('/dashboard?shop=' + shop + '&token=' + accessToken + '&autorun=1');
  } catch (error) {
    res.status(500).send('OAuth failed');
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
    // Fetch all products using Shopify cursor-based pagination (supports 500+)
    let allProducts = [];
    let url = `https://${shop}/admin/api/2024-01/products.json?limit=250`;

    while (url) {
      const response = await axios.get(url, {
        headers: { 'X-Shopify-Access-Token': token },
        timeout: 15000
      });
      const batch = response.data.products || [];
      allProducts = allProducts.concat(batch);

      // Parse Link header for next page cursor
      const linkHeader = response.headers['link'] || '';
      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      url = nextMatch ? nextMatch[1] : null;
    }

    res.json({
      total: allProducts.length,
      products: allProducts.map(p => ({ id: p.id, title: p.title, body: p.body_html, created_at: p.created_at }))
    });
  } catch (error) {
    console.error('/products error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/status', async (req, res) => {
  const { shop } = req.query;
  try {
    const { data, error } = await supabase
      .from('translations')
      .select('locale, status, translated_title, original_title, product_id, created_at')
      .eq('shop', shop)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ total: data.length, translations: data });
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

async function localizeProduct(shop, token, productId, targetLang, locale, tone, glossary) {
  const productRes = await axios.get(
    `https://${shop}/admin/api/2024-01/products/${productId}.json`,
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
    { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${productId}` } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const contents = digestRes.data.data.translatableResource.translatableContent;
  const digests = {};
  contents.forEach(c => { digests[c.key] = c.digest; });

  const cleanBody = (product.body_html || '').replace(/<[^>]*>/g, '').trim();
  const category = product.product_type || '';
  const tags = (product.tags || '').split(',').slice(0, 5).join(', ');
  const vendor = product.vendor || '';

  const prompt = `You are a native ${targetLang} speaker and ecommerce expert.

Glossary (never translate these terms, keep them exactly as written): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${cleanBody
    ? `The merchant has written this product description. Translate it faithfully into ${targetLang}.
Do NOT rewrite, do NOT add new information, do NOT change the style.
Just translate accurately, preserving the original meaning and tone.

TITLE: ${product.title}
DESCRIPTION: ${cleanBody}`
    : `This product has no description yet.
${category ? `Category: ${category}` : ''}
${tags ? `Tags: ${tags}` : ''}

Search the web for "${product.title}" to understand what this product is and how people experience it.
Based on what you find, write a description in ${targetLang} that:
- Reads like a real person wrote it, not a label or ingredient list
- Focuses on the experience, taste, use, or feeling — not the technical composition
- Is 2 sentences maximum
- No bullet points, no ingredient lists, no technical specs
- No generic adjectives like "elegant", "perfect", "exquisite" — use concrete sensory words
- Active voice, present tense
- Max 40 words total
- Sound like a friend recommending the product, not a manufacturer describing it

Also translate the title naturally into ${targetLang}.`
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

  const requestBody = {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 1500,
    messages: [{ role: 'user', content: prompt }]
  };

  if (!cleanBody) {
    requestBody.tools = [{ type: 'web_search_20250305', name: 'web_search' }];
  }

  const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', requestBody, {
    headers: {
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    }
  });

  let rawText = '';
  for (const block of claudeRes.data.content) {
    if (block.type === 'text') rawText += block.text;
  }
  rawText = rawText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  const jsonMatch = rawText.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('No JSON found in response: ' + rawText.substring(0, 100));
  const translated = JSON.parse(jsonMatch[0]);

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
        resourceId: `gid://shopify/Product/${productId}`,
        translations: [
          { key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] },
          { key: 'body_html', value: translated.description, locale, translatableContentDigest: digests['body_html'] }
        ]
      }
    },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );

  await supabase.from('translations').upsert({
    shop,
    product_id: String(productId),
    locale,
    status: 'done',
    original_title: product.title,
    product_handle: product.handle || '',
    translated_title: translated.title,
    translated_description: translated.description,
    meta_title: translated.meta_title,
    meta_description: translated.meta_description
  }, { onConflict: 'shop,product_id,locale' });

  return { product: product.title, translated, shopify: pushRes.data.data.translationsRegister };
}

app.post('/localize', async (req, res) => {
  const { shop, token, productId, targetLang, locale, tone, glossary } = req.body;
  try {
    const result = await localizeProduct(shop, token, productId, targetLang, locale, tone, glossary);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/bulk-localize-all', async (req, res) => {
  const { shop, token, tone, glossary } = req.body;
  try {
    const store = await getStore(shop);
    const savedLocales = store.selected_locales || [];
    const locales = savedLocales.length > 0
      ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
      : await getShopLocales(shop, token);
    // Fetch all products with cursor pagination (supports 500+)
    let products = [];
    let bulkUrl = `https://${shop}/admin/api/2024-01/products.json?limit=250`;
    while (bulkUrl) {
      const batchRes = await axios.get(bulkUrl, { headers: { 'X-Shopify-Access-Token': token } });
      products = products.concat(batchRes.data.products || []);
      const linkHeader = batchRes.headers['link'] || '';
      const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      bulkUrl = nextMatch ? nextMatch[1] : null;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"results":[');
    let first = true;

    for (const product of products) {
      for (const lang of locales) {
        try {
          const result = await localizeProduct(shop, token, product.id, lang.targetLang, lang.locale, tone, glossary);
          if (!first) res.write(',');
          res.write(JSON.stringify({ success: true, locale: lang.locale, ...result }));
          first = false;
        } catch (err) {
          if (!first) res.write(',');
          res.write(JSON.stringify({ product: product.title, locale: lang.locale, success: false, error: err.message }));
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

app.post('/webhook/product-create', async (req, res) => {
  res.status(200).send('OK');
  const rawBody = req.body;
  const shop = req.headers['x-shopify-shop-domain'];
  console.log('=== WEBHOOK HIT ===', shop);
  try {
    const body = Buffer.isBuffer(rawBody) ? JSON.parse(rawBody.toString()) : rawBody;
    if (!body.title || !body.id) return;
    console.log('Calling process-product for:', body.title);
    axios.post(`${APP_URL}/process-product`, {
      shop, productId: body.id, productTitle: body.title
    }, { timeout: 5000 }).catch(err => console.error('Trigger error:', err.message));
  } catch (err) {
    console.error('Webhook error:', err.message);
  }
});

app.post('/process-product', async (req, res) => {
  res.status(200).send('Processing');
  const { shop, productId, productTitle } = req.body;
  try {
    const store = await getStore(shop);
    const token = store.access_token;
    const tone = store.tone || 'professional and elegant';
    const glossary = store.glossary || 'checkout, Shopify';
    console.log('Processing:', productTitle);
    const savedLocales = store.selected_locales || [];
    const locales = savedLocales.length > 0
      ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
      : await getShopLocales(shop, token);
    for (const lang of locales) {
      try {
        await localizeProduct(shop, token, productId, lang.targetLang, lang.locale, tone, glossary);
        console.log(`Done: ${productTitle} in ${lang.targetLang}`);
      } catch (err) {
        console.error(`Error ${lang.locale}:`, err.message);
      }
      await new Promise(resolve => setTimeout(resolve, 300));
    }
  } catch (err) {
    console.error('Process error:', err.message);
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
                await localizeProduct(shop, token, product.id, lang.targetLang, lang.locale, tone, glossary);
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

setInterval(pollNewProducts, 5 * 60 * 1000);
setTimeout(pollNewProducts, 15000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Getoify server running on port ${PORT}`);
});