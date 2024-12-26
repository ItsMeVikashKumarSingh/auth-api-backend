const db = require('../utils/firebaseAdmin');
const { verifyHash, cleanupExpiredSessions } = require('../utils/helpers');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const { hashedUsername, hashedPassword, hashedAppSignature } = req.body;

  try {
    // Verify app signature
    const isAppSignatureValid = await verifyHash(HASHED_APP_SIGNATURE, hashedAppSignature);
    if (!isAppSignatureValid) {
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Fetch user
    const userSnapshot = await db.collection('users').where('username', '==', hashedUsername).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const user = userSnapshot.docs[0].data();

    // Verify password
    const isPasswordValid = await verifyHash(hashedPassword, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Cleanup expired sessions
    await cleanupExpiredSessions(hashedUsername);

    // Create new session
    const token = jwt.sign({ username: hashedUsername }, JWT_SECRET, { expiresIn: '1h' });
    const expiryTimestamp = new Date();
    expiryTimestamp.setHours(expiryTimestamp.getHours() + 1);

    const sessionId = crypto.randomUUID();
    await db.collection('sessions').doc(hashedUsername).set(
      {
        [sessionId]: {
          token,
          expires_at: expiryTimestamp.toISOString(),
        },
      },
      { merge: true }
    );

    return res.status(200).json({ message: 'Login successful.', token });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
