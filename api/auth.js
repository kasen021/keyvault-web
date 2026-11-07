import crypto from 'crypto';

const DB = new Map();

function generateAddress() {
  const bytes = crypto.randomBytes(20);
  return 'KV1' + bytes.toString('hex').toUpperCase();
}

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

function hashPassword(password, salt) {
  return crypto.createHash('sha512').update(password + salt).digest('hex');
}

function encryptPassword(hash, publicKey) {
  return crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(hash)
  ).toString('base64');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { action, password, address } = req.body;

  if (action === 'register') {
    if (!password || password.length < 8) return res.status(400).json({ error: 'Password minimum 8 characters.' });

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(password, salt);
    const { publicKey, privateKey } = generateKeyPair();
    const encryptedPassword = encryptPassword(passwordHash, publicKey);
    const userAddress = generateAddress();
    const createdAt = Date.now();

    DB.set(userAddress, {
      salt,
      encryptedPassword,
      publicKey,
      passwordHashPreview: passwordHash.slice(0, 8),
      createdAt,
      version: 'V3'
    });

    return res.status(200).json({
      success: true,
      address: userAddress,
      publicKey,
      privateKey,
      warning: 'Download your Private Key now. It will NOT be stored on the server. Without it, your encrypted data cannot be recovered.'
    });
  }

  if (action === 'login') {
    if (!password || !address) return res.status(400).json({ error: 'Address and password required.' });

    const user = DB.get(address);
    if (!user) return res.status(401).json({ error: 'Address not found.' });

    const passwordHash = hashPassword(password, user.salt);
    const decrypted = crypto.privateDecrypt(
      { key: req.body.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(user.encryptedPassword, 'base64')
    ).toString();

    if (decrypted !== passwordHash) return res.status(401).json({ error: 'Wrong password.' });

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 30 * 60 * 1000;

    DB.set('session_' + sessionToken, { address, expiresAt });

    return res.status(200).json({
      success: true,
      address,
      sessionToken,
      publicKey: user.publicKey,
      version: user.version
    });
  }

  if (action === 'verify') {
    const { sessionToken } = req.body;
    const session = DB.get('session_' + sessionToken);
    if (!session || Date.now() > session.expiresAt) return res.status(401).json({ error: 'Session expired.' });
    const user = DB.get(session.address);
    return res.status(200).json({ valid: true, address: session.address, publicKey: user.publicKey, version: user.version });
  }

  return res.status(400).json({ error: 'Invalid action.' });
}
