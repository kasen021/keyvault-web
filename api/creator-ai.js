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
        { role: 'system', content: 'You are a cryptography analyst. Answer directly and technically. When asked X or Y: state the answer first, then give technical reasoning. No hedging words: no "however", "but note", "if you mean", "would you like", "it depends", "that said". No analogies. No offers. No questions back. For code: analyze actual structure, state conclusion, explain why with code references.' },
        { role: 'user', content: query }
      ]
    })
  });
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || 'No response.';
  const clean = text
    .replace(/<think>[\s\S]*?<\/think>/g, '')
    .replace(/#{1,6}\s*/g, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/\$\$[^$]+\$\$/g, '[formula]')
    .replace(/\$[^$]+\$/g, '[formula]')
    .trim();
  return res.status(200).json({ result: clean });
}
