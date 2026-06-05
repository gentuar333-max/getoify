/**
 * stripe.js
 * Checkout, webhooks, plan limits, free trial enforcement.
 *
 * Add to index.js:
 *   require('./lib/stripe')(app, { supabase });
 *
 * Vercel env vars required:
 *   STRIPE_SECRET_KEY
 *   STRIPE_WEBHOOK_SECRET
 *   APP_URL
 */

const Stripe = require('stripe');

const PLANS = {
  free: {
    product_limit: 15,
    locale_limit: 2,
    label: 'Free'
  },
  starter: {
    product_limit: 500,
    locale_limit: 3,
    label: 'Starter',
    prices: {
      monthly: 'price_1TeyxDGz46SPfVHRPy424SJS',
      yearly:  'price_1Tez1LGz46SPfVHRk3UpxFJt'
    }
  },
  growth: {
    product_limit: 2500,
    locale_limit: 5,
    label: 'Growth',
    prices: {
      monthly: 'price_1TeyxuGz46SPfVHR1UiZb13T',
      yearly:  'price_1Tez1uGz46SPfVHRF98wFp7M'
    }
  },
  pro: {
    product_limit: 5000,
    locale_limit: 5,
    label: 'Pro',
    prices: {
      monthly: 'price_1TeyyNGz46SPfVHR9DbFBTFh',
      yearly:  'price_1Tez2gGz46SPfVHRbBmJQG3N'
    }
  },
  enterprise: {
    product_limit: 10000,
    locale_limit: 8,
    label: 'Enterprise',
    prices: {
      monthly: 'price_1TeyzuGz46SPfVHR2r8mXaRL',
      yearly:  'price_1Tez4pGz46SPfVHRemrEs8Zo'
    }
  }
};

// Map Stripe price_id → plan name
const PRICE_TO_PLAN = {};
for (const [plan, cfg] of Object.entries(PLANS)) {
  if (cfg.prices) {
    PRICE_TO_PLAN[cfg.prices.monthly] = plan;
    PRICE_TO_PLAN[cfg.prices.yearly]  = plan;
  }
}

module.exports = function registerStripe(app, { supabase }) {
  const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
  const APP_URL = process.env.APP_URL || 'https://getoify.vercel.app';

  // ─── PLAN LIMITS HELPER ────────────────────────────────────────────────────

  /**
   * Check if a shop can translate more products.
   * Returns { allowed: true } or { allowed: false, reason, plan, limit }
   */
  async function checkPlanLimit(shop, requestedProducts, requestedLocales) {
    const { data: store } = await supabase
      .from('stores')
      .select('plan, translations_this_month, product_count_cache')
      .eq('shop', shop)
      .single();

    const planName = store?.plan || 'free';
    const plan = PLANS[planName] || PLANS.free;

    if (requestedProducts > plan.product_limit) {
      return {
        allowed: false,
        reason: `Your ${plan.label} plan supports up to ${plan.product_limit} products. You requested ${requestedProducts}.`,
        plan: planName,
        limit: plan.product_limit,
        upgrade_url: `${APP_URL}/pricing`
      };
    }

    if (requestedLocales > plan.locale_limit) {
      return {
        allowed: false,
        reason: `Your ${plan.label} plan supports up to ${plan.locale_limit} languages.`,
        plan: planName,
        limit: plan.locale_limit,
        upgrade_url: `${APP_URL}/pricing`
      };
    }

    return { allowed: true, plan: planName, limit: plan.product_limit };
  }

  // Expose helper for index.js to import
  app.locals.checkPlanLimit = checkPlanLimit;
  app.locals.PLANS = PLANS;

  // ─── GET PLAN INFO ──────────────────────────────────────────────────────────

  app.get('/plan', async (req, res) => {
    const { shop } = req.query;
    if (!shop) return res.status(400).json({ error: 'Missing shop' });
    try {
      const { data: store } = await supabase
        .from('stores')
        .select('plan, stripe_customer_id, stripe_subscription_id')
        .eq('shop', shop)
        .single();

      const planName = store?.plan || 'free';
      const plan = PLANS[planName] || PLANS.free;
      res.json({
        plan: planName,
        label: plan.label,
        product_limit: plan.product_limit,
        locale_limit: plan.locale_limit,
        has_subscription: !!store?.stripe_subscription_id
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─── CREATE CHECKOUT SESSION ────────────────────────────────────────────────

  app.post('/create-checkout', async (req, res) => {
    const { shop, plan, billing } = req.body;

    if (!shop || !plan || !billing) {
      return res.status(400).json({ error: 'Missing shop, plan or billing' });
    }

    const planCfg = PLANS[plan];
    if (!planCfg || !planCfg.prices) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    const priceId = billing === 'yearly' ? planCfg.prices.yearly : planCfg.prices.monthly;

    try {
      // Get or create Stripe customer
      const { data: store } = await supabase
        .from('stores')
        .select('stripe_customer_id')
        .eq('shop', shop)
        .single();

      let customerId = store?.stripe_customer_id;
      if (!customerId) {
        const customer = await stripe.customers.create({
          metadata: { shop }
        });
        customerId = customer.id;
        await supabase.from('stores').update({ stripe_customer_id: customerId }).eq('shop', shop);
      }

      const session = await stripe.checkout.sessions.create({
        customer: customerId,
        payment_method_types: ['card'],
        line_items: [{ price: priceId, quantity: 1 }],
        mode: 'subscription',
        subscription_data: {
          metadata: { shop, plan }
        },
        success_url: `${APP_URL}/dashboard?shop=${shop}&checkout=success&plan=${plan}`,
        cancel_url:  `${APP_URL}/pricing?shop=${shop}&checkout=cancelled`,
        metadata: { shop, plan }
      });

      res.json({ url: session.url });
    } catch (err) {
      console.error('[stripe] create-checkout error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // ─── CHECKOUT REDIRECT (from pricing.html GET) ──────────────────────────────

  app.get('/checkout', async (req, res) => {
    const { plan, billing, shop } = req.query;
    if (!plan || !billing) return res.redirect('/pricing');

    try {
      const response = await fetch(`${APP_URL}/create-checkout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ shop, plan, billing })
      });
      const data = await response.json();
      if (data.url) return res.redirect(data.url);
      res.redirect(`/pricing?error=checkout_failed`);
    } catch (err) {
      res.redirect(`/pricing?error=checkout_failed`);
    }
  });

  // ─── CUSTOMER PORTAL (manage subscription) ─────────────────────────────────

  app.post('/customer-portal', async (req, res) => {
    const { shop } = req.body;
    if (!shop) return res.status(400).json({ error: 'Missing shop' });

    try {
      const { data: store } = await supabase
        .from('stores')
        .select('stripe_customer_id')
        .eq('shop', shop)
        .single();

      if (!store?.stripe_customer_id) {
        return res.status(404).json({ error: 'No subscription found' });
      }

      const session = await stripe.billingPortal.sessions.create({
        customer: store.stripe_customer_id,
        return_url: `${APP_URL}/dashboard?shop=${shop}`
      });

      res.json({ url: session.url });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─── STRIPE WEBHOOK ─────────────────────────────────────────────────────────

  app.post('/webhook/stripe', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('[stripe webhook] Invalid signature:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    const data = event.data.object;

    try {
      switch (event.type) {

        // Subscription created or updated
        case 'customer.subscription.created':
        case 'customer.subscription.updated': {
          const priceId = data.items?.data?.[0]?.price?.id;
          const planName = PRICE_TO_PLAN[priceId] || 'free';
          const shop = data.metadata?.shop;
          const status = data.status; // active, trialing, past_due, canceled

          if (shop) {
            await supabase.from('stores').update({
              plan: status === 'canceled' ? 'free' : planName,
              stripe_subscription_id: data.id,
              subscription_status: status,
              trial_ends_at: data.trial_end ? new Date(data.trial_end * 1000).toISOString() : null
            }).eq('shop', shop);
            console.log(`[stripe] Plan updated: ${shop} → ${planName} (${status})`);

            // Auto trigger bulk translate after upgrade
            if (status === 'active' && planName !== 'free') {
              const { data: storeData } = await supabase
                .from('stores')
                .select('access_token, tone, glossary')
                .eq('shop', shop)
                .single();
              if (storeData?.access_token) {
                const APP_URL = process.env.APP_URL || 'https://getoify.com';
                fetch(`${APP_URL}/bulk-localize-all`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    shop,
                    token: storeData.access_token,
                    tone: storeData.tone || 'professional and elegant',
                    glossary: storeData.glossary || ''
                  })
                }).catch(err => console.error('[stripe] Auto bulk error:', err.message));
                console.log(`[stripe] Auto bulk translate triggered for ${shop} after upgrade to ${planName}`);
              }
            }
          }
          break;
        }

        // Trial ending soon (3 days before)
        case 'customer.subscription.trial_will_end': {
          const shop = data.metadata?.shop;
          console.log(`[stripe] Trial ending soon for: ${shop}`);
          // Future: send email reminder
          break;
        }

        // Subscription cancelled
        case 'customer.subscription.deleted': {
          const shop = data.metadata?.shop;
          if (shop) {
            await supabase.from('stores').update({
              plan: 'free',
              stripe_subscription_id: null,
              subscription_status: 'canceled'
            }).eq('shop', shop);
            console.log(`[stripe] Subscription cancelled: ${shop} → free`);
          }
          break;
        }

        // Payment failed
        case 'invoice.payment_failed': {
          const customerId = data.customer;
          const { data: store } = await supabase
            .from('stores')
            .select('shop')
            .eq('stripe_customer_id', customerId)
            .single();
          if (store?.shop) {
            await supabase.from('stores').update({
              subscription_status: 'past_due'
            }).eq('shop', store.shop);
            console.log(`[stripe] Payment failed: ${store.shop}`);
          }
          break;
        }

        // Payment succeeded
        case 'invoice.payment_succeeded': {
          const customerId = data.customer;
          const { data: store } = await supabase
            .from('stores')
            .select('shop')
            .eq('stripe_customer_id', customerId)
            .single();
          if (store?.shop) {
            await supabase.from('stores').update({
              subscription_status: 'active'
            }).eq('shop', store.shop);
          }
          break;
        }

        default:
          console.log(`[stripe] Unhandled event: ${event.type}`);
      }
    } catch (err) {
      console.error('[stripe webhook] Handler error:', err.message);
    }

    res.json({ received: true });
  });
};