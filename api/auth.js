import crypto from 'crypto';

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redisCmd(...args) {
  const res = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(args)
  });
  const j = await res.json();
  return j.result;
}

function generateAddress() {
  return 'KV1' + crypto.randomBytes(20).toString('hex').toUpperCase();
}

function hashPassword(password, salt) {
  return crypto.createHash('sha512').update(password + salt).digest('hex');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { action, password, address, sessionToken } = req.body;

  if (action === 'register') {
    if (!password || password.length < 10) return res.status(400).json({ error: 'Password minimal 10 karakter.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(password, salt);
    const userAddress = generateAddress();
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    await redisCmd('SET', 'user:' + userAddress, JSON.stringify({ salt, passwordHash, publicKey, createdAt: Date.now(), version: 'V3' }), 'EX', 60 * 60 * 24 * 365);
    return res.status(200).json({ success: true, address: userAddress, publicKey, privateKey, warning: 'Download your Private Key now. It will NOT be stored on the server.' });
  }

  if (action === 'login') {
    if (!password || !address) return res.status(400).json({ error: 'Address dan password wajib diisi.' });
    const raw = await redisCmd('GET', 'user:' + address);
    if (!raw) return res.status(401).json({ error: 'Address tidak ditemukan.' });
    const user = JSON.parse(raw);
    const passwordHash = hashPassword(password, user.salt);
    if (passwordHash !== user.passwordHash) return res.status(401).json({ error: 'Password salah.' });
    const token = crypto.randomBytes(32).toString('hex');
    await redisCmd('SET', 'session:' + token, address, 'EX', 60 * 60 * 2);
    return res.status(200).json({ success: true, address, sessionToken: token, publicKey: user.publicKey, version: user.version });
  }

  if (action === 'verify') {
    if (!sessionToken) return res.status(400).json({ error: 'Token wajib.' });
    const addr = await redisCmd('GET', 'session:' + sessionToken);
    if (!addr) return res.status(401).json({ error: 'Session expired.' });
    const raw = await redisCmd('GET', 'user:' + addr);
    if (!raw) return res.status(401).json({ error: 'User tidak ditemukan.' });
    const user = JSON.parse(raw);
    return res.status(200).json({ valid: true, address: addr, publicKey: user.publicKey, version: user.version });
  }

  return res.status(400).json({ error: 'Action tidak valid.' });
}
