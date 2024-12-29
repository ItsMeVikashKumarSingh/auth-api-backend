const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const { logLogin } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const crypto = require('crypto');
const { cleanupExpiredSessions } = require('../utils/helpers');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX; // Private key in hex format
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;  // Public key in hex format
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;
const JWT_SECRET = process.env.JWT_SECRET;

module.exports = async (req, res) => {
  logLogin('Incoming login request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logLogin('Login failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    if (!PRIVATE_KEY_HEX || !PUBLIC_KEY_HEX) {
      console.error('PRIVATE_KEY_HEX or PUBLIC_KEY_HEX is not defined. Check your environment variables.');
      return res.status(500).json({
        error: 'Server misconfiguration.',
        details: 'PRIVATE_KEY_HEX or PUBLIC_KEY_HEX is missing.',
      });
    }

    // Validate keys
    if (!/^[0-9a-fA-F]{64}$/.test(PRIVATE_KEY_HEX) || !/^[0-9a-fA-F]{64}$/.test(PUBLIC_KEY_HEX)) {
      console.error('PRIVATE_KEY_HEX or PUBLIC_KEY_HEX is not a valid 64-character hexadecimal string.');
      return res.status(500).json({ error: 'Invalid key format.' });
    }

    const { encryptedData } = req.body;

    if (!encryptedData) {
      logLogin('Login failed: Missing encrypted data.');
      return res.status(400).json({ error: 'Missing encrypted data.' });
    }

    await sodium.ready;

    // Convert keys from hex to Uint8Array
    const privateKey = Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex'));
    const publicKey = Uint8Array.from(Buffer.from(PUBLIC_KEY_HEX, 'hex'));

    // Convert encryptedData from Base64 to Uint8Array
    const sealedBox = Uint8Array.from(Buffer.from(encryptedData, 'base64'));

    // Decrypt the sealed box using the provided public/private keypair
    let decryptedBytes;
    try {
      decryptedBytes = sodium.crypto_box_seal_open(sealedBox, publicKey, privateKey);
    } catch (error) {
      console.error('Decryption failed:', error.message);
      return res.status(400).json({ error: 'Decryption failed.', details: error.message });
    }

    // Parse the decrypted data
    const decryptedData = JSON.parse(Buffer.from(decryptedBytes).toString());
    const { appSignature, username, password } = decryptedData;

    // Verify the app signature
    if (!appSignature || !(await argon2.verify(HASHED_APP_SIGNATURE, appSignature))) {
      logLogin('Login failed: Unauthorized app.', { appSignature });
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Fetch user by username
    const userSnapshot = await db.collection('users').where('username', '==', username).get();
    if (userSnapshot.empty) {
      logLogin('Login failed: Invalid username.', { username });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const user = userSnapshot.docs[0].data();

    // Verify password
    const isPasswordValid = await argon2.verify(user.password_hash, password);
    if (!isPasswordValid) {
      logLogin('Login failed: Invalid password.', { username });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Cleanup expired sessions
    await cleanupExpiredSessions(username);

    // Generate session token
    const sessionId = crypto.randomUUID();
    const expiryTimestamp = new Date();
    expiryTimestamp.setHours(expiryTimestamp.getHours() + 1);

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });

    // Store session in Firestore
    await db.collection('sessions').doc(username).set(
      {
        [sessionId]: {
          token,
          expires_at: expiryTimestamp.toISOString(),
        },
      },
      { merge: true }
    );

    logLogin('Login successful.', { username, sessionId });
    return res.status(200).json({ message: 'Login successful.', token });
  } catch (error) {
    console.error('Error during login:', error);
    logLogin('Login failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};