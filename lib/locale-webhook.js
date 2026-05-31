 
/**
 * locale-webhook.js
 *
 * Kur merchant shton dhe publikon nje gjuhe te re ne Shopify,
 * ky webhook e gjen dhe trigeron perkthimin e te gjitha produkteve
 * per ate gjuhe te re automatikisht.
 *
 * Si e regjistron Shopify: POST /webhook/locale-publish
 * Topic Shopify: locales/create  (ose mund te perdoret locales/update)
 *
 * Si e shton ne index.js (nje rresht):
 *   require('./lib/locale-webhook')(app, { supabase, LOCALE_MAP, APP_URL });
 */

module.exports = function registerLocaleWebhook(app, { supabase, LOCALE_MAP, APP_URL }) {

  app.post('/webhook/locale-publish', async (req, res) => {
    // Pergjigju Shopify menjehere — max 5 sekonda timeout
    res.status(200).send('OK');

    const shop = req.headers['x-shopify-shop-domain'];
    if (!shop) return;

    try {
      const rawBody = req.body;
      const body = Buffer.isBuffer(rawBody)
        ? JSON.parse(rawBody.toString())
        : rawBody;

      // Shopify dergonn: { locale: "es", published: true, ... }
      const locale = body.locale;
      const published = body.published;

      if (!locale || !published) {
        console.log('[locale-webhook] Skipping — locale not published:', body);
        return;
      }

      const targetLang = LOCALE_MAP[locale];
      if (!targetLang) {
        console.log('[locale-webhook] Unknown locale, skipping:', locale);
        return;
      }

      console.log(`[locale-webhook] New locale published: ${locale} (${targetLang}) for shop: ${shop}`);

      // Merr store-in nga Supabase
      const { data: store, error } = await supabase
        .from('stores')
        .select('access_token, selected_locales, tone, glossary')
        .eq('shop', shop)
        .single();

      if (error || !store?.access_token) {
        console.error('[locale-webhook] Store not found or no token:', shop);
        return;
      }

      // Shto gjuhen e re te selected_locales nese nuk eshte
      const currentLocales = store.selected_locales || [];
      if (!currentLocales.includes(locale)) {
        const updatedLocales = [...currentLocales, locale];
        await supabase
          .from('stores')
          .update({ selected_locales: updatedLocales })
          .eq('shop', shop);
        console.log(`[locale-webhook] Added ${locale} to selected_locales for ${shop}`);
      }

      // Triggero bulk translate vetem per kete gjuhe te re
      // Duke perdorur /process-locale endpoint (i ndertuar poshte)
      const triggerUrl = `${APP_URL}/process-locale`;
      const axios = require('axios');
      axios.post(triggerUrl, {
        shop,
        locale,
        targetLang
      }, { timeout: 10000 }).catch(err => {
        console.error('[locale-webhook] Failed to trigger process-locale:', err.message);
      });

    } catch (err) {
      console.error('[locale-webhook] Error:', err.message);
    }
  });

  /**
   * /process-locale — perkthen te gjitha produktet per nje gjuhe te vetme
   * Thirret nga locale-webhook, ose manualisht nese duhet.
   *
   * Body: { shop, locale, targetLang }
   */
  app.post('/process-locale', async (req, res) => {
    const { shop, locale, targetLang } = req.body;
    if (!shop || !locale || !targetLang) {
      return res.status(400).json({ error: 'Missing shop, locale or targetLang' });
    }

    res.json({ ok: true, message: `Started translating all products to ${targetLang} (${locale})` });

    // Vazhdon pas pergjigjes — async ne background
    setImmediate(async () => {
      try {
        const axios = require('axios');

        const { data: store } = await supabase
          .from('stores')
          .select('access_token, tone, glossary')
          .eq('shop', shop)
          .single();

        if (!store?.access_token) {
          console.error('[process-locale] No token for shop:', shop);
          return;
        }

        const token = store.access_token;
        const tone = store.tone || 'professional and elegant';
        const glossary = store.glossary || 'checkout, Shopify';

        // Merr te gjitha produktet
        const SHOPIFY_PRODUCTS_PAGE = 250;
        let products = [];
        let nextUrl = `https://${shop}/admin/api/2024-01/products.json?limit=${SHOPIFY_PRODUCTS_PAGE}`;

        while (nextUrl) {
          const batchRes = await axios.get(nextUrl, {
            headers: { 'X-Shopify-Access-Token': token },
            timeout: 60000
          });
          products = products.concat(batchRes.data.products || []);
          const linkHeader = batchRes.headers['link'] || '';
          const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
          nextUrl = nextMatch ? nextMatch[1] : null;
        }

        console.log(`[process-locale] ${products.length} products to translate to ${targetLang} for ${shop}`);

        // Perkthen nje nga nje
        for (const product of products) {
          try {
            await axios.post(`${APP_URL}/localize`, {
              shop,
              token,
              productId: String(product.id),
              targetLang,
              locale,
              tone,
              glossary
            }, { timeout: 60000 });
            console.log(`[process-locale] Done: ${product.title} → ${locale}`);
          } catch (err) {
            console.error(`[process-locale] Error for ${product.title}:`, err.message);
          }
          // Pause per te mos rritur rate limit
          await new Promise(r => setTimeout(r, 400));
        }

        console.log(`[process-locale] Finished all products for locale ${locale} on ${shop}`);

      } catch (err) {
        console.error('[process-locale] Fatal error:', err.message);
      }
    });
  });

};