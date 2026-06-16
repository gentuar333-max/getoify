require('dotenv').config();
const axios = require('axios');

const TESTS = [
  { title: 'Yogurt',                          lang: 'French'  },
  { title: 'Samsung Galaxy S25 Ultra',        lang: 'French'  },
  { title: 'CeraVe Moisturising Cream 473ml', lang: 'French'  },
  { title: 'Nike Air Max 270',                lang: 'German'  },
  { title: 'Dyson V15 Detect Absolute',       lang: 'Italian' },
];

const LANG_CONFIG = {
  French: {
    tone: 'vous', cta: 'Commandez maintenant',
    sensoryWords: 'arômes, plaisir, saveur, élégance, douceur, art, savoir-faire',
    avoidWords: 'performances, efficacité, fonctionnalité, robuste, solide, durable',
    avoidNote: 'Never repeat "durable", "robuste", "solide" more than once',
    bulletOrder: '1) Specs → 2) Mechanism → 3) Design/emotion → 4) Care/warranty'
  },
  German: {
    tone: 'Sie', cta: 'Jetzt kaufen',
    sensoryWords: 'Genuss, Wärme, Aroma, Qualität, Handwerk, Präzision, Erlebnis',
    avoidWords: 'robust, solide, hochwertig, effizient, funktional, langlebig, strapazierfähig',
    avoidNote: 'Avoid "robust", "hochwertig", "langlebig" — use "gefertigt für den Alltag" or "verarbeitet" instead',
    bulletOrder: '1) Specs → 2) Funktion → 3) Design/Emotion → 4) Pflege/Garantie'
  },
  Italian: {
    tone: 'Lei', cta: 'Acquista ora',
    sensoryWords: 'aroma, calore, piacere, sapore, eleganza, artigianalità, raffinatezza',
    avoidWords: 'robusto, solido, durevole, efficiente, funzionale, performance',
    avoidNote: 'Avoid repeating "robusto" or "durevole"',
    bulletOrder: '1) Specifiche → 2) Meccanismo → 3) Design/Emozione → 4) Cura/Garanzia'
  },
  English: {
    tone: 'you', cta: null,
    sensoryWords: 'quality, warmth, craftsmanship, pleasure, elegance',
    avoidWords: 'robust, solid, durable, efficient, functional, performance',
    avoidNote: 'Avoid repeating the same adjective more than once',
    bulletOrder: '1) Specs → 2) Mechanism → 3) Design/Emotion → 4) Care/Warranty'
  }
};

function detectCategory(title) {
  const t = title.toLowerCase();
  const homeKw     = ['mixer','blender','coffee','nespresso','kettle','air fryer','knife','pan','dyson','kitchenaid','vacuum'];
  const beautyKw   = ['serum','moisturizer','moisturising','cream','cerave','ordinary','roche-posay','neutrogena','retinol','niacinamide'];
  const sportKw    = ['theragun','massage gun','dumbbell','yoga mat','garmin','polar','whoop','oura ring','creatine','whey'];
  const fashionKw  = ['sneaker','shoe','boot','hoodie','jacket','t-shirt','jeans','nike','adidas','bag','watch'];
  if (homeKw.some(k => t.includes(k)))    return 'homeKitchen';
  if (beautyKw.some(k => t.includes(k)))  return 'beautyHealth';
  if (sportKw.some(k => t.includes(k)))   return 'sportFitness';
  if (fashionKw.some(k => t.includes(k))) return 'fashionApparel';
  return 'generic';
}

function buildPrompt(title, targetLang) {
  const langCfg = LANG_CONFIG[targetLang] || LANG_CONFIG.English;
  const cat = detectCategory(title);
  const isGeneric      = cat === 'generic';
  const homeKitchen    = cat === 'homeKitchen';
  const beautyHealth   = cat === 'beautyHealth';
  const sportFitness   = cat === 'sportFitness';
  const fashionApparel = cat === 'fashionApparel';

  return `
TITLE RULES:
- Translate the product name naturally into ${targetLang}
- Add key specs ONLY if confirmed from the product name — never invent
- Format: [Translated name] — [spec1] | [spec2]
- No ALL CAPS, no exclamation marks — max 70 chars

DESCRIPTION RULES:
- Opening sentence: always start with what the customer GETS or FEELS, not what the product IS.
  WRONG: "Yogurt is a fermented dairy product..." RIGHT: "Smooth and creamy — ideal for breakfast, cooking, or a quick snack."
- Write 1-2 opening sentences MAX — SHORT and grounded
- FORBIDDEN words: "Découvrez", "Explorez", "Entdecken Sie", "nuage", "honore", "incontournable", "magie", "transforme"
- Preferred words for ${targetLang}: ${langCfg.sensoryWords}
- AVOID: ${langCfg.avoidWords}
- ${langCfg.avoidNote}
- Address the customer using "${langCfg.tone}"
- Then write exactly 4 bullet points starting with •
- ONE spec per bullet — NEVER combine multiple specs in one bullet.
  WRONG: "• Écran 6,9", 120Hz, 200MP, 5000mAh" (4 specs in 1 bullet — FORBIDDEN)
  RIGHT: "• Écran 6,9" Dynamic AMOLED 2X — 120Hz" then separate bullets for each spec
- Each bullet: number/measurement OR confirmed functional fact — never invent
- RATIO: 80% facts, 20% tone. Total max 120 words.

CATEGORY KNOWLEDGE:

STEP A — KNOWN BRAND + MODEL:
If you recognize the exact product: use ONLY confirmed specs. No invented numbers.
UNCERTAINTY RULE: if not 100% certain → use "up to" or omit. Never fabricate.
PROCESSOR NAME RULE: if you recognize the brand but NOT the exact chip name for this model → write "octa-core processor" or omit. NEVER invent. WRONG: "MediaTek Dimensity 6000" (invented). RIGHT: "Octa-core processor" or skip.
Forbidden generic phrases: "advanced processor", "powerful chip", "high resolution",
"long battery life", "next-generation", "technologie avancée", "de refroidissement avancée"

ONE SPEC PER BULLET — MANDATORY for known products:
- WRONG: "• Snapdragon 8 Elite, écran 6,9", 200MP, 5000mAh" ← SEVERE VIOLATION
- RIGHT:
  • Snapdragon 8 Elite 3nm
  • Écran 6,9" Dynamic AMOLED 2X — 120Hz
  • Caméra principale 200MP — f/1.7
  • Batterie 5000mAh — charge 45W

Priority specs by product type:
- Smartphone → bullet1: processor+nm | bullet2: screen inches+Hz+tech | bullet3: camera MP+aperture | bullet4: battery mAh+charge W
- Earbuds → ANC dB | battery h/case h | BT version+codec | driver mm
- Smartwatch → battery days+mode | sensors | ATM | GPS type
- Vacuum → suction W or Pa | capacity L | runtime min | HEPA yes/no
- Skincare → active ingredient+% | skin type | dermatologist claim | texture
- Running shoe → foam type | drop mm | weight g | outsole rubber

STEP B — KNOWN CATEGORY, UNKNOWN BRAND:
Use "up to" framing for all numbers.

STEP C — UNKNOWN CATEGORY:
Write ONLY what is confirmed from the name.
CRITICAL: Describe what the customer EXPERIENCES — NOT how the product is made.
FOOD RULE: NEVER invent fermentation process, bacterial cultures, probiotic claims,
fat percentage, brand, or origin unless explicitly stated in the title.
If title = "Yogurt" only → write customer experience (taste/texture/use-case) only.

${isGeneric ? `
GENERIC & UNKNOWN PRODUCT RULES:
Write ONLY what is confirmed. Never invent specs or process claims.
FOOD & GROCERY bullet order (use this EXACTLY for food products):
- Bullet 1: texture + taste (e.g. "Texture crémeuse — saveur naturellement acidulée")
- Bullet 2: use-case + occasion (e.g. "Petit-déjeuner, smoothies, sauces, marinades")
- Bullet 3: versatility or serving suggestion — ONLY confirmed facts, NO invented attributes.
  If nothing is confirmed → write "Nature ou aromatisé — à déguster seul ou avec des fruits"
  NEVER write "Sans additifs artificiels" unless confirmed in the title or product info.
- Bullet 4: storage/serving (e.g. "À conserver au réfrigérateur — consommer frais")
FORBIDDEN for food: "fermentation", "bactéries", "cultures", "probiotiques", "digestibilité",
"additifs artificiels" — unless explicitly stated in the title.
TONE: honest, simple, informative — no poetry, no invented features.
` : ''}

${homeKitchen ? `
HOME & KITCHEN RULES:
- Bullet 1: capacity + material
- Bullet 2: motor/mechanism W + speeds
- Bullet 3: accessories included
- Bullet 4: care/warranty (confirmed only)
` : ''}

${beautyHealth ? `
BEAUTY & HEALTH RULES:
- Bullet 1: format + usage duration
- Bullet 2: key active ingredient + technology
- Bullet 3: skin type + dermatologist claim
- Bullet 4: texture + free-from claims
` : ''}

${fashionApparel ? `
FASHION RULES:
- Bullet 1: sole/fabric technology + material
- Bullet 2: construction/fit type
- Bullet 3: key feature or design detail
- Bullet 4: care instructions (confirmed only — never invent wash temperature)
` : ''}

${sportFitness ? `
SPORT & FITNESS RULES:
- Bullet 1: key spec (PPM, weight range, battery days+mode)
- Bullet 2: mechanism or technology name
- Bullet 3: key differentiator vs cheaper models
- Bullet 4: ATM confirmed + weight g
` : ''}

META TITLE (max 60 chars): main keyword first, one key spec if fits, no punctuation at end.
META DESCRIPTION (140-160 chars): start with action verb, one concrete benefit${langCfg.cta ? `, end with "${langCfg.cta}"` : ''}.
FORBIDDEN in meta: "Découvrez", "Explorez", "Entdecken Sie" — use direct verbs instead.

Respond ONLY in this exact JSON — no extra text, no markdown:
{"title":"...","description":"...","meta_title":"...","meta_description":"..."}

---
Product name: "${title}"
No description exists. Write product copy in ${targetLang}.`.trim();
}

async function runTest(title, lang) {
  const prompt = buildPrompt(title, lang);
  const res = await axios.post('https://api.anthropic.com/v1/messages', {
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

  const raw = res.data.content[0].text.trim();
  try {
    const parsed = JSON.parse(raw.match(/\{[\s\S]*\}/)[0]);
    return parsed;
  } catch(e) {
    return { error: 'JSON parse failed', raw };
  }
}

async function main() {
  for (const { title, lang } of TESTS) {
    console.log('\n' + '='.repeat(60));
    console.log(`PRODUCT: "${title}" | LANG: ${lang}`);
    console.log('='.repeat(60));
    try {
      const result = await runTest(title, lang);
      if (result.error) {
        console.log('ERROR:', result.error);
        console.log('RAW:', result.raw);
      } else {
        console.log('TITLE:      ', result.title);
        console.log('DESC:\n' + result.description);
        console.log('META TITLE: ', result.meta_title);
        console.log('META DESC:  ', result.meta_description);
      }
    } catch(e) {
      console.log('FAILED:', e.message);
    }
    await new Promise(r => setTimeout(r, 500));
  }
  console.log('\n' + '='.repeat(60));
  console.log('DONE');
}

main().catch(console.error);