const express = require('express');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();

app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

const { 
  SHOPIFY_API_KEY, 
  SHOPIFY_API_SECRET, 
  SHOPIFY_SCOPES, 
  APP_URL,
  SHOPIFY_ACCESS_TOKEN
} = process.env;

// Mapa e gjuhëve — locale → targetLang
const LOCALE_MAP = {
  'fr': 'French',
  'de': 'German',
  'it': 'Italian',
  'es': 'Spanish',
  'nl': 'Dutch',
  'pt': 'Portuguese',
  'pl': 'Polish',
  'sv': 'Swedish',
  'da': 'Danish',
  'fi': 'Finnish',
  'nb': 'Norwegian',
  'ja': 'Japanese',
  'zh': 'Chinese',
  'ar': 'Arabic'
};

app.get('/', (req, res) => {
  res.json({ status: 'Getoify running', version: '1.0.0' });
});

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
    console.log('Store connected:', shop);
    res.json({ success: true, shop, accessToken });
  } catch (error) {
    res.status(500).send('OAuth failed');
  }
});

// Merr gjuhët aktive nga Shopify Markets
app.get('/locales', async (req, res) => {
  const { shop, token } = req.query;
  if (!shop || !token) return res.status(400).json({ error: 'Missing shop or token' });
  try {
    const response = await axios.get(
      `https://${shop}/admin/api/2026-01/shop/locales.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const locales = response.data.locales
      .filter(l => !l.primary)
      .map(l => ({
        locale: l.locale,
        name: l.name,
        targetLang: LOCALE_MAP[l.locale] || l.name
      }));
    res.json({ locales });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products', async (req, res) => {
  const shop = req.query.shop;
  const token = req.query.token;
  if (!shop || !token) return res.status(400).json({ error: 'Missing shop or token' });
  try {
    const response = await axios.get(`https://${shop}/admin/api/2026-01/products.json?limit=250`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    res.json({
      total: response.data.products.length,
      products: response.data.products.map(p => ({
        id: p.id,
        title: p.title,
        body: p.body_html
      }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/digest', async (req, res) => {
  const { shop, token, productId } = req.query;
  const query = `
    query getTranslatableContent($resourceId: ID!) {
      translatableResource(resourceId: $resourceId) {
        translatableContent { key value digest locale }
      }
    }
  `;
  try {
    const response = await axios.post(
      `https://${shop}/admin/api/2026-01/graphql.json`,
      { query, variables: { resourceId: `gid://shopify/Product/${productId}` } },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function localizeProduct(shop, token, productId, targetLang, locale, tone, glossary) {
  const productRes = await axios.get(
    `https://${shop}/admin/api/2026-01/products/${productId}.json`,
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
    `https://${shop}/admin/api/2026-01/graphql.json`,
    { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${productId}` } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const contents = digestRes.data.data.translatableResource.translatableContent;
  const digests = {};
  contents.forEach(c => { digests[c.key] = c.digest; });

  const cleanBody = (product.body_html || '').replace(/<[^>]*>/g, '');

  const prompt = `You are a professional ecommerce translator and SEO specialist.

Tone: ${tone || 'professional and elegant'}
Glossary (never translate these): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${cleanBody
    ? `Translate this product and generate SEO metadata:
TITLE: ${product.title}
DESCRIPTION: ${cleanBody}`
    : `This product has no description.
Generate a professional 3-5 sentence product description from the title, then translate everything.
TITLE: ${product.title}`
  }

Rules for meta_title (max 60 chars):
- Include main product keyword
- Natural, not keyword-stuffed

Rules for meta_description (max 160 chars):
- Start with action verb (Entdecken, Découvrez, Scopri, Discover)
- Include main product benefit
- Specific to THIS product
- Max 160 chars

Respond ONLY in this exact JSON format, no other text:
{
  "title": "translated title",
  "description": "translated description",
  "meta_title": "SEO title max 60 chars",
  "meta_description": "SEO description max 160 chars"
}`;

  const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1000,
    messages: [{ role: 'user', content: prompt }]
  }, {
    headers: {
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    }
  });

  const translated = JSON.parse(claudeRes.data.content[0].text);

  const mutation = `
    mutation translationsRegister($resourceId: ID!, $translations: [TranslationInput!]!) {
      translationsRegister(resourceId: $resourceId, translations: $translations) {
        translations { key value }
        userErrors { field message }
      }
    }
  `;
  const pushRes = await axios.post(
    `https://${shop}/admin/api/2026-01/graphql.json`,
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

  return {
    product: product.title,
    translated,
    shopify: pushRes.data.data.translationsRegister
  };
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

app.post('/bulk-localize', async (req, res) => {
  const { shop, token, targetLang, locale, tone, glossary } = req.body;

  try {
    const productsRes = await axios.get(
      `https://${shop}/admin/api/2026-01/products.json?limit=250`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const products = productsRes.data.products;
    console.log(`Found ${products.length} products`);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"results":[');
    let first = true;

    for (const product of products) {
      try {
        const result = await localizeProduct(shop, token, product.id, targetLang, locale, tone, glossary);
        if (!first) res.write(',');
        res.write(JSON.stringify({ success: true, ...result }));
        first = false;
      } catch (err) {
        if (!first) res.write(',');
        res.write(JSON.stringify({ product: product.title, success: false, error: err.message }));
        first = false;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    res.write(']}');
    res.end();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bulk localize të gjitha gjuhët aktive automatikisht
app.post('/bulk-localize-all', async (req, res) => {
  const { shop, token, tone, glossary } = req.body;

  try {
    // Merr gjuhët aktive nga Shopify
    const localesRes = await axios.get(
      `https://${shop}/admin/api/2026-01/shop/locales.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const locales = localesRes.data.locales
      .filter(l => !l.primary)
      .map(l => ({
        locale: l.locale,
        targetLang: LOCALE_MAP[l.locale] || l.name
      }));

    console.log('Active locales:', locales);

    // Merr të gjitha produktet
    const productsRes = await axios.get(
      `https://${shop}/admin/api/2026-01/products.json?limit=250`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const products = productsRes.data.products;
    console.log(`Found ${products.length} products, ${locales.length} languages`);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"results":[');
    let first = true;

    for (const product of products) {
      for (const lang of locales) {
        try {
          const result = await localizeProduct(
            shop, token, product.id,
            lang.targetLang, lang.locale,
            tone, glossary
          );
          if (!first) res.write(',');
          res.write(JSON.stringify({ success: true, locale: lang.locale, ...result }));
          first = false;
        } catch (err) {
          if (!first) res.write(',');
          res.write(JSON.stringify({ product: product.title, locale: lang.locale, success: false, error: err.message }));
          first = false;
        }
        await new Promise(resolve => setTimeout(resolve, 500));
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

  try {
    const body = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString()) : req.body;
    const product = body;
    const shop = req.headers['x-shopify-shop-domain'];
    const token = SHOPIFY_ACCESS_TOKEN;

    if (!product.title) {
      console.log('Webhook — empty product, skipping');
      return;
    }

    console.log('Webhook — new product:', product.title, 'from:', shop);

    // Merr gjuhët aktive automatikisht
    const localesRes = await axios.get(
      `https://${shop}/admin/api/2026-01/shop/locales.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const locales = localesRes.data.locales
      .filter(l => !l.primary)
      .map(l => ({
        locale: l.locale,
        targetLang: LOCALE_MAP[l.locale] || l.name
      }));

    // Lokalizo në të gjitha gjuhët aktive
    for (const lang of locales) {
      try {
        await localizeProduct(
          shop, token, product.id,
          lang.targetLang, lang.locale,
          'professional and elegant',
          'checkout, Shopify'
        );
        console.log(`Webhook — localized ${product.title} in ${lang.targetLang}`);
      } catch (err) {
        console.error(`Webhook — error ${lang.locale}:`, err.message);
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }

  } catch (err) {
    console.error('Webhook error:', err.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Getoify server running on port ${PORT}`);
});