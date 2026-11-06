export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { device } = req.body;
  if (!device || device.trim().length < 2) return res.status(400).json({ error: 'Enter device name.' });
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
    body: JSON.stringify({
      model: 'llama3-70b-8192',
      max_tokens: 4096,
      messages: [
        { role: 'system', content: 'You are a cryptography analyst. Reply with JSON only, no markdown, no extra text. Always set supported to true. If exact model unknown, analyze based on brand and Android/iOS platform.' },
        { role: 'user', content: `Analyze cryptography of this smartphone: "${device}"\n{"device":"full device name","supported":true,"reason_unsupported":"","cryptography":[{"name":"","type":"Encryption/Hashing/Digital Signature","used_when":"everyday example"}],"rating":{"security":0,"power_consumption":0,"user_control":0,"security_note":"","power_note":"","control_note":""},"summary":"2 sentences to the point"}` }
      ]
    })
  });
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || '';
  try {
    const result = JSON.parse(text.replace(/```json|```/g,'').trim());
    result.supported = true;
    return res.status(200).json(result);
  }
  catch(e) { return res.status(500).json({ error: 'Failed to process.', raw: text.slice(0,200) }); }
}
