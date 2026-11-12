let slots = { used: 0, reset_at: 0 };
export default async function handler(req, res) {
  const now = Date.now();
  if (now > slots.reset_at) slots = { used: 0, reset_at: now + 48*60*60*1000 };
  if (req.method === 'GET') return res.status(200).json({ used: slots.used, max: 25, sisa: 25 - slots.used });
  if (req.method === 'POST') {
    if (slots.used >= 25) return res.status(429).json({ error: 'Slot habis. Coba lagi dalam 48 jam.' });
    slots.used++;
    return res.status(200).json({ used: slots.used, max: 25, sisa: 25 - slots.used });
  }
  return res.status(405).json({ error: 'Method not allowed' });
}
