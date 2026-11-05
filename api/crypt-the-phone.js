export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { device } = req.body;
  if (!device || device.trim().length < 2) return res.status(400).json({ error: 'Enter device name.' });
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
    body: JSON.stringify({
      model: 'llama-3.1-8b-instant',
      max_tokens: 8192,
      messages: [
        { role: 'system', content: 'You are a cryptography analyst. Reply with JSON only, no markdown, no extra text. If the device brand is known (Xiaomi, Redmi, Samsung, Apple, Google, OPPO, Vivo, etc.), treat it as supported even if the exact model is unknown — analyze based on the brand and Android/iOS platform.' },
        { role: 'user', content: `Analyze cryptography of this smartphone: "${device}"\n{"device":"full device name","supported":true,"reason_unsupported":"","cryptography":[{"name":"","type":"Encryption/Hashing/Digital Signature","used_when":"everyday example"}],"rating":{"security":0,"power_consumption":0,"user_control":0,"security_note":"","power_note":"","control_note":""},"summary":"2 sentences, to the point"}` }
      ]
    })
  });
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || '';
  try { return res.status(200).json(JSON.parse(text.replace(/```json|```/g,'').trim())); }
  catch { return res.status(500).json({ error: 'Failed to process response.' }); }
}
