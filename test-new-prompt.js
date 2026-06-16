require('dotenv').config();
const axios = require('axios');

const PROMPT_VERSION = '2.0';

const CORE_RULES = `
You are a native [TARGET_LANG] ecommerce copywriter. 
Your job: write product copy that SELLS, not poetry.

GOLDEN RULES:
1. MERCHANT SPECS = GROUND TRUTH (highest priority)
2. If unsure → use "up to" or omit. NEVER invent.
3. 80% specs, 20% tone. Not reverse.
4. Every bullet must have a number, measurement, or confirmed fact.
5. ZERO hallucination — if not in title/image, don't write it.

FORBIDDEN WORDS (never use):
- "advanced", "powerful", "high resolution", "long battery life"
- "innovative", "precision intentionnelle", "double action"
- "robust", "durable", "solid" (more than once)
- "transforms", "magical", "revolutionary"

UNIT CONVERSION (auto-apply for FR/DE/IT/ES/NL/PT/PL/SV):
- inches → cm (×2.54)
- sq in → cm² (×6.45)
- lbs → kg (×0.453)
- oz → g (×28.3)
- °F → °C ((F-32)×5/9)
Format: metric first, imperial in parentheses. FR: "4,5 kg" (comma decimal)
`;

const CATEGORY_RULES = {
  smartphone: `
SMARTPHONE — mandatory specs:
- Bullet 1: Display — inches + Hz + tech (AMOLED/LCD)
- Bullet 2: Camera — MP + aperture + OIS yes/no
- Bullet 3: Processor — EXACT name (Snapdragon 8 Gen 2, Exynos 2200)
- Bullet 4: Battery — mAh + charge W + "cable sold separately" if true
- NEVER write "included" for charger unless 100% confirmed
- ALWAYS mention IP rating if present in title
- NEVER write "octa-core" alone — exact chip name only
`,
  sportFitness: `
SPORT & FITNESS — mandatory checks:
- "Portable" ONLY if weight < 0.8kg confirmed
- Battery: ALWAYS specify mode (smartwatch/GPS/expedition)
- Water resistance: 5ATM = rain only, 10ATM = swimming, 20ATM+ = diving
- NEVER mix variant specs (Solar = MIP, NOT AMOLED)
- Subscription products: NEVER write price — "see [brand].com"
`,
  skincare: `
SKINCARE — mandatory:
- Active ingredient + % (Niacinamide 10%, Retinol 0.1%)
- Skin type target
- "Dermatologically tested" only if confirmed
- NEVER use "formule avancee" — replace with real tech name
- The Ordinary: clinical tone, no marketing fluff
`,
  homeKitchen: `
HOME & KITCHEN:
- Capacity + material
- Motor W + speeds
- Accessories included
- NEVER use "chaleur" for non-heating appliances
- Nespresso: specify Vertuo vs Original (incompatible!)
`,
  fashion: `
FASHION:
- Material composition %
- Fit type (Regular/Slim/Loose)
- Care instructions
- NEVER "timeless" without year/fact
- NEVER "true to size" unless confirmed
`
};

const LANG_RULES = {
  French: {
    tone: 'vous',
    cta: 'Commandez maintenant',
    sensory: 'plaisir, precision, elegance, onctueux, raffine',
    avoid: 'robuste, solide, durable, performant, efficace',
    example: '✓ Ecran AMOLED 6,4" — 120 Hz, HDR10+, 1450 nits'
  },
  German: {
    tone: 'Sie',
    cta: 'Jetzt kaufen',
    sensory: 'Genuss, Qualitat, Handwerk, Präzision',
    avoid: 'robust, solide, hochwertig, effizient',
    example: '✓ AMOLED-Display 6,4" — 120 Hz, HDR10+, 1450 nits'
  },
  Italian: {
    tone: 'Lei',
    cta: 'Acquista ora',
    sensory: 'piacere, artigianalita, raffinatezza, eleganza',
    avoid: 'robusto, solido, durevole, performante',
    example: '✓ Display AMOLED 6,4" — 120 Hz, HDR10+, 1450 nits'
  }
};

const MERCHANT_SPEC_RULE = `
MERCHANT SPEC EXTRACTION — HIGHEST PRIORITY:

If product title contains " | " or " — ":
1. SPLIT title by " | " and " — "
2. EVERYTHING after first " — " or between " | " = CONFIRMED SPEC
3. USE these specs EXACTLY in bullets — never override
4. NEVER invent specs beyond what merchant provided

Example:
Title: "Samsung Galaxy S23 FE — 6.4" | 50MP | 4000mAh"
→ Extracted: 6.4", 50MP, 4000mAh
→ Bullets MUST use these exact numbers

Title: "Nike Pegasus 41 — ReactX | 10mm | 280g | Daily Trainer"
→ Extracted: ReactX, 10mm, 280g, Daily Trainer
→ Bullets MUST use: "Mousse ReactX", "Drop 10mm", "280g", "Daily Trainer"
`;

const VALIDATION_RULE = `
SELF-VALIDATION — MANDATORY before output:

Check 1: HALLUCINATION
- Did I invent any spec not in title/image? → If YES, remove or use "up to"
- Did I write "Gen 5" when title says "Gen 4"? → If YES, fix
- Did I write "AMOLED" for "Solar" variant? → If YES, fix

Check 2: MERCHANT SPECS
- Did I use ALL specs from title? → If NO, add missing ones
- Did I override merchant spec with internal knowledge? → If YES, revert

Check 3: DANGEROUS CLAIMS
- Did I write "included" for charger/cable? → Verify before keeping
- Did I write specific subscription price? → Remove, use "see brand.com"
- Did I write "5ATM" for diving? → Fix or remove

Check 4: BULLET QUALITY
- Does every bullet have a number/measurement/fact? → If NO, fix
- Any bullet > 12 words? → If YES, shorten
- Any repeated adjective across title+prose+bullets? → If YES, replace

Only after ALL checks pass, output JSON.
`;

const OUTPUT_FORMAT = `
OUTPUT — EXACT JSON, no markdown, no extra text:
{"title":"[Translated name] — [spec1] | [spec2] | [spec3]","description":"[1-2 short sentences] • [Bullet 1: spec+number] • [Bullet 2: mechanism] • [Bullet 3: design/emotion] • [Bullet 4: care/warranty]","meta_title":"[max 60 chars, keyword first]","meta_description":"[140-160 chars, action verb, benefit, CTA]"}

TITLE RULES:
- Max 70 chars
- Include 2-3 key specs from merchant title
- No ALL CAPS, no exclamation marks

DESCRIPTION RULES:
- 1-2 opening sentences MAX, short, grounded
- Exactly 4 bullets starting with •
- Bullet 1: spec with number
- Bullet 2: how it works (mechanism)
- Bullet 3: design/emotion (no repeated adjectives)
- Bullet 4: care/warranty (confirmed only)
- 80% facts, 20% tone
- Max 120 words total

META TITLE: max 60 chars, main keyword first, one spec if fits
META DESCRIPTION: 140-160 chars, action verb, concrete benefit, CTA if available
`;

function detectCategory(product) {
  const title = (product.title || '').toLowerCase();
  if (title.includes('phone') || title.includes('galaxy') || title.includes('iphone') || title.includes('pixel')) return 'smartphone';
  if (title.includes('shoe') || title.includes('sneaker') || title.includes('trainer') || title.includes('running')) return 'sportFitness';
  if (title.includes('serum') || title.includes('cream') || title.includes('moisturizer') || title.includes('spf')) return 'skincare';
  if (title.includes('mixer') || title.includes('blender') || title.includes('nespresso') || title.includes('coffee')) return 'homeKitchen';
  if (title.includes('jean') || title.includes('shirt') || title.includes('jacket') || title.includes('dress')) return 'fashion';
  return 'generic';
}

function extractSpecsFromTitle(title) {
  const parts = title.split(/ — | \| /);
  return parts.slice(1).map(s => s.trim()).filter(Boolean);
}

function selectModel(title, price) {
  const t = title.toLowerCase();
  if (price > 500 ||
      t.includes('theragun') || t.includes('garmin') || t.includes('peloton') ||
      t.includes('oura') || t.includes('whoop') ||
      (t.includes('samsung') && t.includes('galaxy'))) {
    return { model: 'claude-sonnet-4-6', thinking: true };
  }
  if (price > 50 || t.includes('solar') || t.includes('pro plus') ||
      t.includes('ultra') || t.includes('max') || t.includes('fe')) {
    return { model: 'claude-sonnet-4-6', thinking: false };
  }
  return { model: 'claude-haiku-4-5-20251001', thinking: false };
}

function validateOutput(parsed, product) {
  const errors = [];
  const title = (product.title || '').toLowerCase();
  const desc = (parsed.description || '').toLowerCase();

  if (parsed.title.includes('Gen 5') && !title.includes('gen 5')) errors.push('HALLUCINATION: Gen 5 not in title');
  if (title.includes('solar') && desc.includes('amoled')) errors.push('VARIANT_MIXUP: Solar vs AMOLED');
  if (title.includes('fe') && desc.includes('snapdragon 8 gen 2')) errors.push('VARIANT_MIXUP: FE wrong chip');
  if (desc.match(/\d+\s*jours?/) && !desc.match(/smartwatch|gps|expedition/)) errors.push('BATTERY_NO_MODE');
  if (desc.includes('included') && !title.includes('included')) errors.push('UNVERIFIED_INCLUDED');
  if (desc.match(/€\d+[.,]?\d*\s*\/\s*mois/) && !title.includes('€')) errors.push('INVENTED_PRICE');

  const merchantSpecs = extractSpecsFromTitle(product.title);
  for (const spec of merchantSpecs) {
    const numbers = spec.match(/\d+/g);
    if (numbers) {
      const found = numbers.some(n => desc.includes(n));
      if (!found) errors.push(`MISSING_SPEC: ${spec}`);
    }
  }

  const bullets = parsed.description.split('•').filter(b => b.trim());
  if (bullets.length !== 4) errors.push(`BULLET_COUNT: Expected 4, got ${bullets.length}`);

  return { valid: errors.length === 0, errors };
}

function createFallback(product, errors) {
  return {
    title: product.title,
    description: `[FLAG: ${errors.join(', ')}] — Manual review required`,
    meta_title: product.title.substring(0, 60),
    meta_description: product.title.substring(0, 160)
  };
}

async function callClaude(model, prompt, thinking) {
  const payload = {
    model,
    max_tokens: thinking ? 8000 : 600,
    messages: [{ role: 'user', content: prompt }]
  };
  if (thinking) {
    payload.thinking = { type: 'enabled', budget_tokens: 4000 };
    payload['anthropic-beta'] = 'interleaved-thinking-2025-05-14';
  }
  return axios.post('https://api.anthropic.com/v1/messages', payload, {
    headers: {
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      ...(thinking ? { 'anthropic-beta': 'interleaved-thinking-2025-05-14' } : {}),
      'content-type': 'application/json'
    },
    timeout: 60000
  });
}

function parseClaudeResponse(response) {
  let raw = '';
  for (const block of response.data.content) {
    if (block.type === 'text') raw += block.text;
  }
  raw = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('No JSON in response');
  return JSON.parse(match[0]);
}

async function run(title, lang, price) {
  const product = { title, product_type: '' };
  const category = detectCategory(product);
  const catRules = CATEGORY_RULES[category] || '';
  const langRules = LANG_RULES[lang] || LANG_RULES.French;
  const specs = extractSpecsFromTitle(title);
  const { model, thinking } = selectModel(title, price);

  const prompt = [
    CORE_RULES,
    MERCHANT_SPEC_RULE,
    catRules,
    `LANGUAGE: ${lang}`,
    `TONE: ${langRules.tone}`,
    `SENSORY WORDS: ${langRules.sensory}`,
    `AVOID: ${langRules.avoid}`,
    VALIDATION_RULE,
    OUTPUT_FORMAT,
    `\nPRODUCT: "${title}"`,
    specs.length ? `MERCHANT SPECS: ${specs.join(' | ')}` : '',
    `\nWrite product copy in ${lang} based ONLY on the title above.`
  ].filter(Boolean).join('\n\n');

  const response = await callClaude(model, prompt, thinking);
  const parsed = parseClaudeResponse(response);
  const validation = validateOutput(parsed, product);

  return { parsed, model, thinking, validation };
}

const TESTS = [
  { title: 'Samsung Galaxy S25 Ultra', lang: 'French',  price: 1299 },
  { title: 'Samsung Galaxy S23 FE',   lang: 'French',  price: 499  },
  { title: 'iPhone 15 Pro',           lang: 'English', price: 1099 },
  { title: 'Nike Air Max 270',        lang: 'German',  price: 130  },
  { title: 'CeraVe Moisturising Cream 473ml', lang: 'French', price: 18 },
  { title: 'Yogurt',                  lang: 'French',  price: 2    },
];

async function main() {
  for (const { title, lang, price } of TESTS) {
    console.log('\n' + '='.repeat(60));
    console.log(`PRODUCT: "${title}" | LANG: ${lang} | PRICE: €${price}`);
    console.log('='.repeat(60));
    try {
      const { parsed, model, thinking, validation } = await run(title, lang, price);
      console.log(`MODEL: ${model}${thinking ? ' + Thinking' : ''}`);
      if (!validation.valid) console.log('VALIDATION ERRORS:', validation.errors);
      console.log('TITLE:    ', parsed.title);
      console.log('DESC:\n' + parsed.description);
      console.log('META:     ', parsed.meta_title);
      console.log('META DESC:', parsed.meta_description);
    } catch(e) {
      console.log('FAILED:', e.message);
    }
    await new Promise(r => setTimeout(r, 800));
  }
  console.log('\n' + '='.repeat(60));
  console.log('DONE');
}

main().catch(console.error);
