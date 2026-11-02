export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { device } = req.body;
  if (!device || device.trim().length < 2) return res.status(400).json({ error: 'Masukkan nama perangkat.' });
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1000, messages: [{ role: 'user', content: `Kamu analis kriptografi profesional. Analisis perangkat: "${device}". Balas JSON saja:\n{"device":"nama perangkat","supported":true,"reason_unsupported":"","cryptography":[{"name":"","type":"Enkripsi/Hashing/Tanda Tangan Digital","used_when":""}],"rating":{"security":0,"power_consumption":0,"user_control":0,"security_note":"","power_note":"","control_note":""},"summary":""}` }] })
  });
  const data = await response.json();
  const text = data.content?.[0]?.text || '';
  try { return res.status(200).json(JSON.parse(text.replace(/```json|```/g,'').trim())); }
  catch { return res.status(500).json({ error: 'Gagal memproses.' }); }
}
