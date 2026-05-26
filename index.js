const express = require('express');
const dotenv = require('dotenv');
const axios = require('axios');
const crypto = require('crypto');

dotenv.config();

const app = express();

// Webhook needs raw body
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

const { 
  SHOPIFY_API_KEY, 
  SHOPIFY_API_SECRET, 
  SHOPIFY_SCOPES, 
  APP_URL,
  SHOPIFY_ACCESS_TOKEN
} = process.env;

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
        translatableContent {
          key
          value
          digest
          locale
        }
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

app.post('/localize', async (req, res) => {
  const { shop, token, productId, targetLang, locale, tone, glossary } = req.body;

  try {
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

Translate this product and generate SEO metadata:
TITLE: ${product.title}
DESCRIPTION: ${cleanBody}

Rules for meta_title (max 60 chars):
- Include main product keyword
- Include brand benefit
- Natural, not keyword-stuffed

Rules for meta_description (max 160 chars):
- Start with action verb (Entdecken, Découvrez, Scopri, Discover)
- Include main product benefit
- Mention target customer (sensitive skin, daily use, etc)
- End with soft call to action
- Must be specific to THIS product, not generic

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

    res.json({
      success: true,
      product: product.title,
      translated,
      shopify: pushRes.data.data.translationsRegister
    });

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
        console.log(`Localizing: ${product.title}`);

        const digestQuery = `
          query getTranslatableContent($resourceId: ID!) {
            translatableResource(resourceId: $resourceId) {
              translatableContent { key value digest locale }
            }
          }
        `;
        const digestRes = await axios.post(
          `https://${shop}/admin/api/2026-01/graphql.json`,
          { query: digestQuery, variables: { resourceId: `gid://shopify/Product/${product.id}` } },
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
Translate this product and generate SEO metadata:
TITLE: ${product.title}
DESCRIPTION: ${cleanBody}
Rules for meta_title (max 60 chars):
- Include main product keyword
- Natural, not keyword-stuffed
Rules for meta_description (max 160 chars):
- Start with action verb
- Include main product benefit
- Specific to THIS product
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
              resourceId: `gid://shopify/Product/${product.id}`,
              translations: [
                { key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] },
                { key: 'body_html', value: translated.description, locale, translatableContentDigest: digests['body_html'] }
              ]
            }
          },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
        );

        const result = {
          product: product.title,
          success: true,
          translated,
          errors: pushRes.data.data.translationsRegister.userErrors
        };

        if (!first) res.write(',');
        res.write(JSON.stringify(result));
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

app.post('/webhook/product-create', async (req, res) => {
  res.status(200).send('OK');

  try {
    const body = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString()) : req.body;
    const product = body;
    const shop = req.headers['x-shopify-shop-domain'];
    const token = SHOPIFY_ACCESS_TOKEN;

    console.log('Webhook — new product:', product.title, 'from:', shop);

    await axios.post(`${APP_URL}/localize`, {
      shop,
      token,
      productId: product.id,
      targetLang: 'German',
      locale: 'de',
      tone: 'professional and elegant',
      glossary: 'checkout, Shopify'
    });

    console.log('Webhook — localized:', product.title);
  } catch (err) {
    console.error('Webhook error:', err.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Getoify server running on port ${PORT}`);
});