const db = require('../utils/firebaseAdmin');
const { logRegister } = require('../utils/logger');
require('dotenv').config();

const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  logRegister('Incoming request for registration.', req.body);

  if (req.method !== 'POST') {
    logRegister('Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const { hashedUsername, hashedPassword, hashedAppSignature } = req.body;

  try {
    // Verify app signature
    if (hashedAppSignature !== HASHED_APP_SIGNATURE) {
      logRegister('Unauthorized app attempt.', req.body);
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Check if username already exists
    const userSnapshot = await db.collection('users').where('username', '==', hashedUsername).get();
    if (!userSnapshot.empty) {
      logRegister('Attempt to register with an existing username.', { hashedUsername });
      return res.status(400).json({ error: 'Username already exists.' });
    }

    // Store the user in Firestore
    await db.collection('users').add({
      username: hashedUsername,
      password_hash: hashedPassword, // Already hashed by the client
    });

    logRegister('User registered successfully.', { hashedUsername });
    return res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    logRegister('Registration failed.', { error: error.message });
    return res.status(500).json({ error: 'Registration failed.', details: error.message });
  }
};
