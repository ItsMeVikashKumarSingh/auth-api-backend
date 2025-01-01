const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
const { DateTime } = require('luxon');
const crypto = require('crypto');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming login request.', { headers: req.headers });

  if (req.method !== 'POST') {
    console.log('Login failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Login failed: Missing encrypted data.');
      return res.status(400).json({ error: 'Missing encrypted data.' });
    }

    await sodium.ready;

    const privateKey = Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex'));
    const publicKey = Uint8Array.from(Buffer.from(PUBLIC_KEY_HEX, 'hex'));
    const sealedBox = Uint8Array.from(Buffer.from(encryptedData, 'base64'));

    let decryptedBytes;
    try {
      decryptedBytes = sodium.crypto_box_seal_open(sealedBox, publicKey, privateKey);
    } catch (error) {
      console.error('Decryption failed:', error.message);
      return res.status(400).json({ error: 'Decryption failed.', details: error.message });
    }

    const decryptedData = JSON.parse(Buffer.from(decryptedBytes).toString());
    const { username, password, clientPublicKey } = decryptedData;

    if (!username || typeof username !== 'string' || username.trim() === '') {
      console.log('Login failed: Missing or invalid username.', { username });
      return res.status(400).json({ error: 'Missing or invalid username.' });
    }

    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);

      if (!usernameHash || typeof usernameHash !== 'string') {
        console.log('Login failed: Invalid username hash.', { username });
        continue;
      }

      try {
        const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();

        if (regUserDoc.exists) {
          userUUID = regUserDoc.data().uuid;
          break;
        }
      } catch (error) {
        console.error('Firestore query error:', error.message);
        console.log('Login failed: Firestore query error.', { usernameHash, error: error.message });
        return res.status(500).json({ error: 'Database query error.', details: error.message });
      }
    }

    if (!userUUID) {
      console.log('Login failed: User not found.', { username });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Fetch user data and continue login process...
    console.log('Login successful for user:', userUUID);
    return res.status(200).json({ message: 'Login successful.' });
  } catch (error) {
    console.error('Error during login:', error);
    console.log('Login failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
