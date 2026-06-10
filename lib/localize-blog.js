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

async function generateArticleCopy(article, targetLang, glossary) {
  const cleanBody = (article.body_html || '').replace(/<[^>]*>/g, '').trim();
  if (!cleanBody && !article.title) throw new Error('Article has no content');

  const prompt = `You are a native ${targetLang} speaker and professional content writer.

Glossary (keep these terms exactly as written, never translate): ${glossary || 'checkout, Shopify'}
Target language: ${targetLang}

Translate this blog article faithfully into ${targetLang}.
Do NOT rewrite, do NOT add information, preserve structure and tone exactly.
Preserve all HTML tags if present.

TITLE: ${article.title}
${cleanBody ? `CONTENT: ${cleanBody.substring(0, 3000)}` : ''}

Respond ONLY in this exact JSON format, no extra text, no markdown backticks:
{"title":"...","body_html":"...","meta_title":"...","meta_description":"...","summary":"..."}

META TITLE: max 60 chars.
META DESCRIPTION: 140-160 chars, start with action verb in ${targetLang}.
SUMMARY (excerpt): max 160 chars summary of the article in ${targetLang}.`;

  const claudeRes = await axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 2000,
    messages: [{ role: 'user', content: prompt }]
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
  if (!parsed.title) throw new Error('Missing title');
  return parsed;
}

async function localizeArticle(shop, token, blogId, articleId, targetLang, locale, glossary) {
  // Merr article nga Shopify
  const artRes = await axios.get(
    `https://${shop}/admin/api/2024-01/blogs/${blogId}/articles/${articleId}.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  const article = artRes.data.article;
  if (!article) throw new Error('Article not found: ' + articleId);

  // Merr digests
  const digestQuery = `
    query getTranslatableContent($resourceId: ID!) {
      translatableResource(resourceId: $resourceId) {
        translatableContent { key value digest locale }
      }
    }
  `;
  const digestRes = await axios.post(
    `https://${shop}/admin/api/2024-01/graphql.json`,
    { query: digestQuery, variables: { resourceId: `gid://shopify/Article/${articleId}` } },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  const contents = digestRes.data.data?.translatableResource?.translatableContent || [];
  const digests = {};
  contents.forEach(c => { digests[c.key] = c.digest; });

  // Gjenero perkthim me Claude
  const translated = await generateArticleCopy(article, targetLang, glossary);

  if (!translated.meta_title) {
    translated.meta_title = translated.title.substring(0, 60);
  }
  if (!translated.meta_description) {
    translated.meta_description = (translated.summary || translated.title).substring(0, 160);
  }

  // Regjistro te Shopify
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
        resourceId: `gid://shopify/Article/${articleId}`,
        translations: [
          ...(digests['title'] ? [{ key: 'title', value: translated.title, locale, translatableContentDigest: digests['title'] }] : []),
          ...(digests['body_html'] ? [{ key: 'body_html', value: translated.body_html || translated.description || '', locale, translatableContentDigest: digests['body_html'] }] : []),
          ...(digests['summary_html'] && translated.summary ? [{ key: 'summary_html', value: translated.summary, locale, translatableContentDigest: digests['summary_html'] }] : []),
          ...(translated.meta_title && digests['meta_title'] ? [{ key: 'meta_title', value: translated.meta_title, locale, translatableContentDigest: digests['meta_title'] }] : []),
          ...(translated.meta_description && digests['meta_description'] ? [{ key: 'meta_description', value: translated.meta_description, locale, translatableContentDigest: digests['meta_description'] }] : [])
        ]
      }
    },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );

  const shopifyResult = pushRes.data.data?.translationsRegister;
  if (shopifyResult?.userErrors?.length > 0) {
    console.error('[blog] Shopify userErrors:', JSON.stringify(shopifyResult.userErrors));
  } else {
    console.log('[blog] Translations pushed OK:', article.title, locale);
  }

  // Ruaj ne Supabase
  await supabase.from('blog_translations').upsert({
    shop,
    blog_id: String(blogId),
    article_id: String(articleId),
    locale,
    status: 'done',
    original_title: article.title,
    translated_title: translated.title,
    meta_title: translated.meta_title,
    meta_description: translated.meta_description
  }, { onConflict: 'shop,article_id,locale' });

  return { article_id: articleId, article: article.title, translated, shopify: shopifyResult };
}

async function bulkLocalizeBlogs(shop, token, glossary, savedLocales) {
  const locales = savedLocales.length > 0
    ? savedLocales.map(l => ({ locale: l, targetLang: LOCALE_MAP[l] || l }))
    : [];

  if (!locales.length) {
    console.warn('[blogs] No locales configured for', shop);
    return [];
  }

  // Merr te gjitha blogs
  const blogsRes = await axios.get(
    `https://${shop}/admin/api/2024-01/blogs.json`,
    { headers: { 'X-Shopify-Access-Token': token } }
  );
  const blogs = blogsRes.data.blogs || [];

  // Skip articles qe jane perkthyer tashme
  const { data: existingRows } = await supabase
    .from('blog_translations')
    .select('article_id, locale')
    .eq('shop', shop);
  const translatedSet = new Set((existingRows || []).map(r => `${r.article_id}:${r.locale}`));

  const results = [];
  for (const blog of blogs) {
    // Merr te gjitha articles per kete blog
    const artRes = await axios.get(
      `https://${shop}/admin/api/2024-01/blogs/${blog.id}/articles.json?limit=250`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    const articles = artRes.data.articles || [];

    for (const article of articles) {
      for (const lang of locales) {
        const key = `${String(article.id)}:${lang.locale}`;
        if (translatedSet.has(key)) continue;
        try {
          const result = await localizeArticle(shop, token, blog.id, article.id, lang.targetLang, lang.locale, glossary);
          results.push({ success: true, ...result });
        } catch(e) {
          console.error('[blog] Error:', article.title, lang.locale, e.message);
          results.push({ success: false, article_id: article.id, locale: lang.locale, error: e.message });
        }
        await new Promise(r => setTimeout(r, 300));
      }
    }
  }

  console.log(`[blogs] Bulk done: ${results.filter(r => r.success).length}/${results.length} for ${shop}`);
  return results;
}

module.exports = { localizeArticle, bulkLocalizeBlogs };