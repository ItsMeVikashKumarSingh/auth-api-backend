const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const { logLogin } = require('../utils/logger');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { utils, ed25519 } = require('@noble/ed25519'); // For decryption
const crypto = require('crypto');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX; // Store as hex in .env
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;
const JWT_SECRET = process.env.JWT_SECRET;

module.exports = async (req, res) => {
  logLogin('Incoming login request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logLogin('Login failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      logLogin('Login failed: Missing encrypted data.');
      return res.status(400).json({ error: 'Missing encrypted data.' });
    }

    // Decrypt the encrypted message
    const privateKeyBytes = utils.hexToBytes(PRIVATE_KEY_HEX);
    const decryptedBytes = await ed25519.decrypt(encryptedData, privateKeyBytes);
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
    await cleanupExpiredSessions(hashedUsername);

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
    logLogin('Login failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
