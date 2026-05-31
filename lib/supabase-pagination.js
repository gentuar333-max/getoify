const PAGE_SIZE = 1000;

/**
 * Fetch all matching rows from Supabase (PostgREST defaults to 1000 rows per request).
 */
async function fetchAllRows(supabase, { table, select, eq = {}, order }) {
  const rows = [];
  let from = 0;

  while (true) {
    let query = supabase.from(table).select(select);
    for (const [column, value] of Object.entries(eq)) {
      query = query.eq(column, value);
    }
    if (order) {
      query = query.order(order.column, { ascending: order.ascending !== false });
    }
    const { data, error } = await query.range(from, from + PAGE_SIZE - 1);
    if (error) throw error;
    if (!data || data.length === 0) break;
    rows.push(...data);
    if (data.length < PAGE_SIZE) break;
    from += PAGE_SIZE;
  }

  return rows;
}

module.exports = { fetchAllRows, PAGE_SIZE };
