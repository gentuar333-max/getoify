const axios = require('axios');

axios.post('https://getoify-test.myshopify.com/admin/api/2026-01/webhooks.json', {
  webhook: {
    topic: 'products/create',
    address: 'https://getoify.vercel.app/webhook/product-create',
    format: 'json'
  }
}, {
  headers: {
    'X-Shopify-Access-Token': 'shpua_ef789f03a9d1b35c5a8310547fa77a55',
    'Content-Type': 'application/json'
  }
})
.then(r => console.log(JSON.stringify(r.data, null, 2)))
.catch(e => console.error(e.message));