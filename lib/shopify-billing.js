/**
 * shopify-billing.js
 * Shopify Billing API — per App Store installs.
 * Works alongside stripe.js (Stripe for direct installs).
 *
 * Add to index.js:
 *   require('./lib/shopify-billing')(app, { supabase });
 *
 * How it works:
 * 1. After OAuth, check if shop needs a subscription
 * 2. Create recurring charge via Shopify Billing API
 * 3. Redirect merchant to confirm in Shopify Admin
 * 4. Shopify redirects back to /billing/callback
 * 5. Activate charge and update plan in Supabase
 */

const axios = require('axios');

const SHOPIFY_PLANS = {
  starter: {
    label: 'Getoify Starter',
    price: 19.00,
    trial_days: 14,
    product_limit: 500,
    locale_limit: 3
  },
  growth: {
    label: 'Getoify Growth',
    price: 49.00,
    trial_days: 14,
    product_limit: 2500,
    locale_limit: 5
  },
  pro: {
    label: 'Getoify Pro',
    price: 99.00,
    trial_days: 14,
    product_limit: 5000,
    locale_limit: 5
  }
};

module.exports = function registerShopifyBilling(app, { supabase }) {
  const APP_URL = process.env.APP_URL || 'https://getoify.vercel.app';

  // ─── CREATE RECURRING CHARGE ────────────────────────────────────────────────

  app.get('/billing/start', async (req, res) => {
    const { shop, plan } = req.query;

    if (!shop || !plan) {
      return res.status(400).send('Missing shop or plan');
    }

    const planCfg = SHOPIFY_PLANS[plan];
    if (!planCfg) {
      return res.status(400).send('Invalid plan');
    }

    try {
      const { data: store } = await supabase
        .from('stores')
        .select('access_token')
        .eq('shop', shop)
        .single();

      if (!store?.access_token) {
        return res.redirect(`/auth?shop=${shop}`);
      }

      const chargeRes = await axios.post(
        `https://${shop}/admin/api/2024-01/recurring_application_charges.json`,
        {
          recurring_application_charge: {
            name: planCfg.label,
            price: planCfg.price,
            return_url: `${APP_URL}/billing/callback?shop=${shop}&plan=${plan}`,
            trial_days: planCfg.trial_days,
            test: process.env.NODE_ENV !== 'production' // test mode in dev
          }
        },
        {
          headers: {
            'X-Shopify-Access-Token': store.access_token,
            'Content-Type': 'application/json'
          }
        }
      );

      const charge = chargeRes.data.recurring_application_charge;
      const confirmUrl = charge.confirmation_url;

      // Save pending charge id
      await supabase.from('stores').update({
        shopify_charge_id: String(charge.id),
        shopify_charge_status: 'pending',
        pending_plan: plan
      }).eq('shop', shop);

      console.log(`[shopify-billing] Charge created for ${shop}: ${charge.id}`);
      res.redirect(confirmUrl);

    } catch (err) {
      console.error('[shopify-billing] Error creating charge:', err.response?.data || err.message);
      res.redirect(`/pricing?shop=${shop}&error=billing_failed`);
    }
  });

  // ─── BILLING CALLBACK (after merchant confirms) ─────────────────────────────

  app.get('/billing/callback', async (req, res) => {
    const { shop, plan, charge_id } = req.query;

    if (!shop || !charge_id) {
      return res.redirect(`/dashboard?shop=${shop}&billing=cancelled`);
    }

    try {
      const { data: store } = await supabase
        .from('stores')
        .select('access_token')
        .eq('shop', shop)
        .single();

      if (!store?.access_token) {
        return res.redirect(`/auth?shop=${shop}`);
      }

      // Get charge status from Shopify
      const chargeRes = await axios.get(
        `https://${shop}/admin/api/2024-01/recurring_application_charges/${charge_id}.json`,
        { headers: { 'X-Shopify-Access-Token': store.access_token } }
      );

      const charge = chargeRes.data.recurring_application_charge;

      if (charge.status !== 'accepted') {
        console.log(`[shopify-billing] Charge declined: ${shop}`);
        await supabase.from('stores').update({
          shopify_charge_status: 'declined',
          pending_plan: null
        }).eq('shop', shop);
        return res.redirect(`/pricing?shop=${shop}&billing=declined`);
      }

      // Activate charge
      await axios.post(
        `https://${shop}/admin/api/2024-01/recurring_application_charges/${charge_id}/activate.json`,
        { recurring_application_charge: charge },
        { headers: { 'X-Shopify-Access-Token': store.access_token, 'Content-Type': 'application/json' } }
      );

      const planCfg = SHOPIFY_PLANS[plan] || SHOPIFY_PLANS.starter;

      // Update plan in Supabase
      await supabase.from('stores').update({
        plan: plan,
        shopify_charge_id: String(charge_id),
        shopify_charge_status: 'active',
        subscription_status: 'active',
        pending_plan: null,
        trial_ends_at: charge.trial_ends_on || null
      }).eq('shop', shop);

      console.log(`[shopify-billing] Plan activated: ${shop} → ${plan}`);
      res.redirect(`/dashboard?shop=${shop}&billing=success&plan=${plan}`);

    } catch (err) {
      console.error('[shopify-billing] Callback error:', err.response?.data || err.message);
      res.redirect(`/dashboard?shop=${shop}&billing=error`);
    }
  });

  // ─── GET BILLING STATUS ─────────────────────────────────────────────────────

  app.get('/billing/status', async (req, res) => {
    const { shop } = req.query;
    if (!shop) return res.status(400).json({ error: 'Missing shop' });

    try {
      const { data: store } = await supabase
        .from('stores')
        .select('plan, shopify_charge_id, shopify_charge_status, subscription_status, trial_ends_at')
        .eq('shop', shop)
        .single();

      res.json({
        plan: store?.plan || 'free',
        charge_id: store?.shopify_charge_id,
        charge_status: store?.shopify_charge_status,
        subscription_status: store?.subscription_status || 'free',
        trial_ends_at: store?.trial_ends_at
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─── CANCEL SUBSCRIPTION ────────────────────────────────────────────────────

  app.post('/billing/cancel', async (req, res) => {
    const { shop } = req.body;
    if (!shop) return res.status(400).json({ error: 'Missing shop' });

    try {
      const { data: store } = await supabase
        .from('stores')
        .select('access_token, shopify_charge_id')
        .eq('shop', shop)
        .single();

      if (store?.shopify_charge_id && store?.access_token) {
        await axios.delete(
          `https://${shop}/admin/api/2024-01/recurring_application_charges/${store.shopify_charge_id}.json`,
          { headers: { 'X-Shopify-Access-Token': store.access_token } }
        );
      }

      await supabase.from('stores').update({
        plan: 'free',
        shopify_charge_id: null,
        shopify_charge_status: 'cancelled',
        subscription_status: 'cancelled'
      }).eq('shop', shop);

      console.log(`[shopify-billing] Cancelled: ${shop} → free`);
      res.json({ ok: true });

    } catch (err) {
      console.error('[shopify-billing] Cancel error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });
};