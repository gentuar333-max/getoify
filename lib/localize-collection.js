const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const LOCALE_MAP = {
  'fr': 'French', 'de': 'German', 'it': 'Italian', 'es': 'Spanish',
  'nl': 'Dutch', 'pt': 'Portuguese', 'pl': 'Polish', 'sv': 'Swedish',
  'da': 'Danish', 'fi': 'Finnish', 'nb': 'Norwegian', 'ja': 'Japanese',
  'zh': 'Chinese', 'ar': 'Arabic', 'hi': 'Hindi', 'id': 'Indonesian',
  'en': 'English'
};

async function generateCollectionCopy(collection, targetLang, glossary) {
  const cleanBody = (collection.body_html || '').replace(/<[^>]*>/g, '').trim();

  const prompt = `You are a native ${targetLang} speaker and professional ecommerce copywriter.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

${cleanBody
  ? `Translate this collection title and description faithfully into ${targetLang}.
Do NOT rewrite, do NOT add information, preserve tone exactly.

TITLE: ${collection.title}
DESCRIPTION: ${cleanBody}`
  : `Write a short, elegant collection description in ${targetLang} for this collection.
Max 2 sentences. No bullet points. Professional ecommerce tone.

COLLECTION NAME: ${collection.title}`
}

Respond ONLY in this exact JSON format, no extra text, no markdown backticks:
{"title":"...","description":"...","meta_title":"...","meta_description":"..."}

META TITLE: max 60 chars, main keyword first.
META DESCRIPTION: 140-160 chars, start with action verb in ${targetLang}.`;

  const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 600,
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
  if (!parsed.title) throw new Error('Missing title');
  return parsed;
}

async function localizeCollection(shop, token, collectionId, targetLang, locale, glossary) {
  // Merr collection nga Shopify
  const collRes = await axios.get(
    `https://${shop}/admin/api/2024-01/custom_collections/${collectionId}.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  ).catch(() =>
    axios.get(
      `https://${shop}/admin/api/2024-01/smart_collections/${collectionId}.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    )
  );

  const collection = collRes.data.custom_collection || collRes.data.smart_collection;
  if (!collection) throw new Error('Collection not found: ' + collectionId);

  // Merr digests per Shopify Translations API
  const digestQuery = `
    query getTranslatableContent($resourceId: ID!) {
      translatableResource(resourceId: $resourceId) {
        translatableContent { key value digest locale }
      }
    }
  `;
  const digestRes = await axios.post(
    `https://${shop}/admin/api/2024-01/graphql.json`,
    { query: digestQuery, variables: { resourceId: `gid://shopify/Collection/${collectionId}` } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const contents = digestRes.data.data?.translatableResource?.translatableContent || [];
  const digests = {};
  contents.forEach(c => { digests[c.key] = c.digest; });

  // Gjenero perkthim me Claude
  const translated = await generateCollectionCopy(collection, targetLang, glossary);

  if (!translated.meta_title) {
    translated.meta_title = translated.title.substring(0, 60);
  }
  if (!translated.meta_description) {
    translated.meta_description = (translated.description || translated.title).substring(0, 160);
  }

  // Regjistro perkthimin te Shopify
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
        resourceId: `gid://shopify/Collection/${collectionId}`,
        translations: [
          ...(digests['title'] ? [{ key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] }] : []),
          ...(digests['body_html'] ? [{ key: 'body_html', value: translated.description, locale, translatableContentDigest: digests['body_html'] }] : []),
          ...(translated.meta_title && digests['meta_title'] ? [{ key: 'meta_title', value: translated.meta_title, locale, translatableContentDigest: digests['meta_title'] }] : []),
          ...(translated.meta_description && digests['meta_description'] ? [{ key: 'meta_description', value: translated.meta_description, locale, translatableContentDigest: digests['meta_description'] }] : [])
        ]
      }
    },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );

  const shopifyResult = pushRes.data.data?.translationsRegister;
  if (shopifyResult?.userErrors?.length > 0) {
    console.error('[collection] Shopify userErrors:', JSON.stringify(shopifyResult.userErrors));
  } else {
    console.log('[collection] Translations pushed OK:', collection.title, locale);
  }

  // Ruaj ne Supabase
  await supabase.from('collection_translations').upsert({
    shop,
    collection_id: String(collectionId),
    locale,
    status: 'done',
    original_title: collection.title,
    original_description: collection.body_html || '',
    translated_title: translated.title,
    translated_description: translated.description,
    meta_title: translated.meta_title,
    meta_description: translated.meta_description
  }, { onConflict: 'shop,collection_id,locale' });

  return { collection_id: collectionId, collection: collection.title, translated, shopify: shopifyResult };
}

async function bulkLocalizeCollections(shop, token, tone, glossary, savedLocales) {
  const locales = savedLocales.length > 0
    ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
    : [];

  if (!locales.length) {
    console.warn('[collections] No locales configured for', shop);
    return [];
  }

  // Merr te gjitha collections (custom + smart)
  const [customRes, smartRes] = await Promise.all([
    axios.get(`https://${shop}/admin/api/2024-01/custom_collections.json?limit=250`,
      { headers: { 'X-Shopify-Access-Token': token } }),
    axios.get(`https://${shop}/admin/api/2024-01/smart_collections.json?limit=250`,
      { headers: { 'X-Shopify-Access-Token': token } })
  ]);

  const allCollections = [
    ...(customRes.data.custom_collections || []),
    ...(smartRes.data.smart_collections || [])
  ];

  // Skip collections qe jane perkthyer tashme
  const { data: existingRows } = await supabase
    .from('collection_translations')
    .select('collection_id, locale')
    .eq('shop', shop);
  const translatedSet = new Set((existingRows || []).map(r => `${r.collection_id}:${r.locale}`));

  const results = [];
  for (const collection of allCollections) {
    for (const lang of locales) {
      const key = `${String(collection.id)}:${lang.locale}`;
      if (translatedSet.has(key)) continue;
      try {
        const result = await localizeCollection(shop, token, collection.id, lang.targetLang, lang.locale, glossary);
        results.push({ success: true, ...result });
      } catch(e) {
        console.error('[collection] Error:', collection.title, lang.locale, e.message);
        results.push({ success: false, collection_id: collection.id, locale: lang.locale, error: e.message });
      }
      await new Promise(r => setTimeout(r, 300));
    }
  }

  console.log(`[collections] Bulk done: ${results.filter(r => r.success).length}/${results.length} for ${shop}`);
  return results;
}

module.exports = { localizeCollection, bulkLocalizeCollections };