export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { device } = req.body;
  if (!device || device.trim().length < 2) return res.status(400).json({ error: 'Masukkan nama perangkat.' });
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
    body: JSON.stringify({
      model: 'llama-3.1-8b-instant',
      max_tokens: 8192,
      messages: [
        { role: 'system', content: 'Balas JSON saja. Tanpa teks lain, tanpa markdown.' },
        { role: 'user', content: `Analisis kriptografi smartphone: "${device}"\n{"device":"","supported":true,"reason_unsupported":"","cryptography":[{"name":"","type":"Enkripsi/Hashing/Tanda Tangan Digital","used_when":""}],"rating":{"security":0,"power_consumption":0,"user_control":0,"security_note":"","power_note":"","control_note":""},"summary":""}` }
      ]
    })
  });
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || '';
  try { return res.status(200).json(JSON.parse(text.replace(/```json|```/g,'').trim())); }
  catch { return res.status(500).json({ error: 'Gagal memproses.' }); }
}
