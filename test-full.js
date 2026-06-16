require('dotenv').config();
const axios = require('axios');
const TESTS = [
  { title: 'Yogurt', lang: 'French' },
  { title: 'Samsung Galaxy S25 Ultra', lang: 'French' },
  { title: 'CeraVe Moisturising Cream 473ml', lang: 'French' },
  { title: 'Nike Air Max 270', lang: 'German' },
  { title: 'Dyson V15 Detect Absolute', lang: 'Italian' },
  { title: 'Theragun Pro Plus', lang: 'French' },
  { title: 'Scented Candle', lang: 'French' },
];
async function main() {
  for (const { title, lang } of TESTS) {
    console.log('\n' + '='.repeat(50));
    console.log('PRODUCT: ' + title + ' | ' + lang);
    console.log('='.repeat(50));
    try {
      const r = await axios.post('http://localhost:3000/test-prompt', { title, lang }, { timeout: 30000 });
      const d = r.data;
      console.log('TITLE: ' + d.title);
      console.log('DESC:\n' + d.description);
      console.log('META: ' + d.meta_title);
    } catch(e) { console.log('FAILED:', e.message); }
    await new Promise(r => setTimeout(r, 600));
  }
  console.log('\nDONE');
}
main().catch(console.error);