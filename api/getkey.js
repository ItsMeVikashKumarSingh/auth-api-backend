const argon2 = require('argon2');
const { logProtected } = require('../utils/logger'); // Log utility
require('dotenv').config();

const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  logProtected('Incoming request for app signature verification.', { headers: req.headers });

  if (req.method !== 'POST') {
    logProtected('App signature verification failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { appSignature } = req.body;

    if (!appSignature) {
      logProtected('App signature verification failed: Missing app signature.');
      return res.status(400).json({ error: 'Missing app signature.' });
    }

    // Verify the app signature
    const isValid = await argon2.verify(HASHED_APP_SIGNATURE, appSignature);
    if (!isValid) {
      logProtected('App signature verification failed: Invalid signature.', { appSignature });
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    logProtected('App signature verification successful.', { appSignature });
    return res.status(200).json({
      message: 'App signature verified successfully.',
      publicKey: PUBLIC_KEY_HEX, // Return the public key
    });
  } catch (error) {
    logProtected('App signature verification failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Verification failed.', details: error.message });
  }
};
