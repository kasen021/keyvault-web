import crypto from 'crypto';
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { mode, input1, input2, hash_input } = req.body;
  if (mode === 'compare') {
    if (!input1 || !input2) return res.status(400).json({ error: 'Masukkan dua input.' });
    const hash1 = crypto.createHash('sha256').update(input1).digest('hex');
    const hash2 = crypto.createHash('sha256').update(input2).digest('hex');
    return res.status(200).json({ hash1, hash2, match: hash1 === hash2, algorithm: 'SHA-256' });
  }
  if (mode === 'decrypt') {
    if (!hash_input) return res.status(400).json({ error: 'Masukkan hash.' });
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 500, messages: [{ role: 'user', content: `Identifikasi hash: "${hash_input}". Balas JSON:\n{"hash_type":"","possible_plaintext":"","reversible":false,"explanation":""}` }] })
    });
    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    try { return res.status(200).json(JSON.parse(text.replace(/```json|```/g,'').trim())); }
    catch { return res.status(500).json({ error: 'Gagal memproses.' }); }
  }
  return res.status(400).json({ error: 'Mode tidak dikenali.' });
}
