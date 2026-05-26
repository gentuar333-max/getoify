const axios = require('axios');

axios.post('http://localhost:3000/bulk-localize', {
  shop: 'getoify-test.myshopify.com',
  token: 'shpua_ef789f03a9d1b35c5a8310547fa77a55',
  targetLang: 'German',
  locale: 'de',
  tone: 'elegant and professional',
  glossary: 'checkout, Shopify'
}, { responseType: 'text' })
.then(r => console.log(r.data))
.catch(e => console.error(e.message));