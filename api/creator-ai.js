export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Query required.' });
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + process.env.GROQ_API_KEY },
    body: JSON.stringify({
      model: 'qwen/qwen3.8-27b',
      max_tokens: 2048,
      messages: [
        { role: 'system', content: 'You are an expert cryptography analyst assistant. Help analyze cryptographic implementations, algorithms, protocols, and security vulnerabilities. Be technical, precise, and to the point. No analogies. No poetry. Just direct cryptographic analysis.' },
        { role: 'user', content: query }
      ]
    })
  });
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || 'No response.';
  const clean = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    const formatted = clean
    .replace(/####+\s*/g, '')
    .replace(/###\s*/g, '')
    .replace(/##\s*/g, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/\$\$[^$]+\$\$/g, '[formula]')
    .replace(/\$[^$]+\$/g, '[formula]')
    .replace(/^\s*[-*]\s+/gm, '- ')
    .trim();
  return res.status(200).json({ result: formatted });
}
