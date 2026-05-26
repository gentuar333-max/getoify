const axios = require('axios');

axios.get('https://getoify.vercel.app/locales', {
  params: {
    shop: 'getoify-test.myshopify.com',
    token: 'shpua_ef789f03a9d1b35c5a8310547fa77a55'
  }
})
.then(r => console.log(JSON.stringify(r.data, null, 2)))
.catch(e => console.error(e.message));