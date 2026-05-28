const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  'https://vicuwjsbgchthujktfhp.supabase.co',
  'sb_secret_kGDiX6iJZQpdoOIF0EIqtg_vWyBuHPG'
);

async function run() {
  const { data } = await supabase
    .from('translations')
    .select('product_id, translated_title')
    .eq('shop', 'getoify-test.myshopify.com')
    .eq('product_id', '9239311679650');
  
  console.log('Burger in Supabase:', JSON.stringify(data));
}
run();