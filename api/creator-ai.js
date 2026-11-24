export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Query required.' });
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + process.env.GROQ_API_KEY },
    body: JSON.stringify({
      model: 'qwen/qwen3.8-27b',
      max_tokens: 1024,
      messages: [
        { role: 'system', content: 'You are a cryptography analyst. STRICT RULES: 1. Answer exactly what is asked, nothing more. 2. FORBIDDEN words: "however", "but", "note", "worth mentioning", "if you mean", "if what you mean", "one thing", "that said", "nonetheless", "nevertheless", "keep in mind", "it depends", "apakah kamu mau", "would you like". 3. If asked X or Y: answer X or Y. One word answer first, then one sentence proof maximum. 4. No analogies. No caveats. No offers. No questions back to user. 5. For code analysis: read the actual code structure, give direct conclusion.' },
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
