const db = require('../utils/firebaseAdmin');
const { verifyHash } = require('../utils/helpers');
require('dotenv').config();

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

    // Check if username exists
    const userSnapshot = await db.collection('users').where('username', '==', hashedUsername).get();
    if (!userSnapshot.empty) {
      return res.status(400).json({ error: 'Username already exists.' });
    }

    // Store user
    await db.collection('users').add({
      username: hashedUsername,
      password_hash: hashedPassword,
    });

    return res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    return res.status(500).json({ error: 'Registration failed.', details: error.message });
  }
};
