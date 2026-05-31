/** Canonical Shopify product_id for DB keys and API lookups (never use array index). */
function normalizeProductId(productId) {
  if (productId === null || productId === undefined || productId === '') {
    throw new Error('Missing product_id');
  }
  const id = String(productId).trim();
  if (!/^\d+$/.test(id)) {
    throw new Error('Invalid product_id: ' + id);
  }
  return id;
}

module.exports = { normalizeProductId };
