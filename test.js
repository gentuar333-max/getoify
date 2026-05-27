const axios = require('axios');

axios.get('https://getoify.vercel.app/status', {
  params: { shop: 'getoify-test.myshopify.com' }
})
.then(r => console.log(JSON.stringify(r.data, null, 2)))
.catch(e => console.error(e.message));