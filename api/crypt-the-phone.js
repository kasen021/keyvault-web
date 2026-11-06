export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { device } = req.body;
  if (!device || device.trim().length < 2) return res.status(400).json({ error: 'Enter device name.' });
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
    body: JSON.stringify({
      model: 'qwen/qwen3-8b',
      max_tokens: 4096,
      messages: [
        { role: 'system', content: 'You are a smartphone advisor. Reply with JSON only, no markdown, no thinking tags, no extra text.' },
        { role: 'user', content: `Analyze this smartphone for a buyer: "${device}"\n{"device":"full name","supported":true,"reason_unsupported":"","cryptography":[{"name":"","type":"Encryption/Hashing/Digital Signature","used_when":""}],"rating":{"security":0,"power_consumption":0,"user_control":0,"security_note":"","power_note":"","control_note":""},"facts":["fact 1","fact 2","fact 3","fact 4","fact 5"],"gaming":{"capable":true,"best_games":[""],"max_hours":0,"note":""},"summary":"2 sentences"}` }
      ]
    })
  });
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || '';
  try {
    const clean = text.replace(/<think>[\s\S]*?<\/think>/g,'').replace(/```json|```/g,'').trim();
    const result = JSON.parse(clean);
    result.supported = true;
    return res.status(200).json(result);
  }
  catch(e) { return res.status(500).json({ error: 'Failed to process.', raw: text.slice(0,300) }); }
}
