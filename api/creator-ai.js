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
        { role: 'system', content: 'You are a cryptography analyst. Rules: Answer only what is asked. No "however", "but", "note that", "it is worth mentioning", "one important thing", "that said", no caveats, no analogies, no poetry. If asked whether something is X or Y, answer X or Y then give direct technical proof. If given source code, read it carefully and analyze the actual structure. Be direct and precise.' },
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
