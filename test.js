const axios = require('axios');

axios.post('https://getoify.vercel.app/bulk-localize-all', {
  shop: 'getoify-test.myshopify.com',
  token: 'shpua_ef789f03a9d1b35c5a8310547fa77a55',
  tone: 'elegant and professional',
  glossary: 'checkout, Shopify'
}, { responseType: 'text' })
.then(r => console.log(r.data))
.catch(e => console.error(e.message));