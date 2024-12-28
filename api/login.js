const db = require('../utils/firebaseAdmin');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { logLogin } = require('../utils/logger');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  logLogin('Incoming request for login.', req.body);

  if (req.method !== 'POST') {
    logLogin('Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const { hashedUsername, hashedPassword, hashedAppSignature } = req.body;

  try {
    // Verify app signature
    const isAppSignatureValid = await argon2.verify(HASHED_APP_SIGNATURE, hashedAppSignature);
    if (!isAppSignatureValid) {
      logLogin('Unauthorized app attempt.', req.body);
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Fetch user by username
    const userSnapshot = await db.collection('users').where('username', '==', hashedUsername).get();
    if (userSnapshot.empty) {
      logLogin('Invalid credentials: Username not found.', { hashedUsername });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const user = userSnapshot.docs[0].data();

    // Verify password
    const isPasswordValid = await argon2.verify(user.password_hash, hashedPassword);
    if (!isPasswordValid) {
      logLogin('Invalid credentials: Password mismatch.', { hashedUsername });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Cleanup expired sessions
    await cleanupExpiredSessions(hashedUsername);

    // Extend or create session
    const expiryTimestamp = new Date();
    expiryTimestamp.setHours(expiryTimestamp.getHours() + 1);
    const sessionId = crypto.randomUUID();
    const token = jwt.sign({ username: hashedUsername }, JWT_SECRET, { expiresIn: '1h' });

    await db.collection('sessions').doc(hashedUsername).set(
      {
        [sessionId]: {
          token,
          expires_at: expiryTimestamp.toISOString(),
        },
      },
      { merge: true }
    );

    logLogin('Login successful.', { hashedUsername, sessionId });
    return res.status(200).json({ message: 'Login successful.', token });
  } catch (error) {
    logLogin('Login failed.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
