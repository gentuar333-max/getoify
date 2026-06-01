const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeProductId } = require('../lib/product-id');

test('normalizeProductId accepts numeric and string Shopify IDs', () => {
  assert.equal(normalizeProductId(9239311679650), '9239311679650');
  assert.equal(normalizeProductId('9239311679650'), '9239311679650');
});

test('normalizeProductId rejects missing or invalid IDs', () => {
  assert.throws(() => normalizeProductId(''), /Missing product_id/);
  assert.throws(() => normalizeProductId(null), /Missing product_id/);
  assert.throws(() => normalizeProductId('abc'), /Invalid product_id/);
});

test('translation rows map by product_id not array position', () => {
  const rows = [];
  for (let i = 0; i < 100; i++) {
    const productId = String(9000000000000 + i);
    rows.push({
      product_id: productId,
      locale: 'de',
      translated_title: `Title-${productId}`,
      meta_title: `Meta-${productId}`,
      meta_description: `Desc-${productId}`,
    });
  }

  // Shuffle to simulate unordered DB / API results
  for (let i = rows.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [rows[i], rows[j]] = [rows[j], rows[i]];
  }

  const byProduct = {};
  for (const row of rows) {
    const pid = normalizeProductId(row.product_id);
    byProduct[pid] = row;
  }

  for (let i = 0; i < 100; i++) {
    const productId = String(9000000000000 + i);
    const row = byProduct[productId];
    assert.ok(row, 'missing row for ' + productId);
    assert.equal(row.translated_title, `Title-${productId}`);
    assert.equal(row.meta_title, `Meta-${productId}`);
    assert.equal(row.meta_description, `Desc-${productId}`);
  }
});
