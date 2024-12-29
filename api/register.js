const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const { logRegister } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX; // Private key in hex format
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  logRegister('Incoming registration request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logRegister('Registration failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    if (!PRIVATE_KEY_HEX) {
      console.error('PRIVATE_KEY_HEX is not defined. Check your environment variables.');
      return res.status(500).json({ error: 'Server misconfiguration.', details: 'PRIVATE_KEY_HEX is missing.' });
    }

    if (!/^[0-9a-fA-F]+$/.test(PRIVATE_KEY_HEX)) {
      console.error('PRIVATE_KEY_HEX is not a valid hexadecimal string.');
      return res.status(500).json({ error: 'Server misconfiguration.', details: 'Invalid PRIVATE_KEY_HEX format.' });
    }

    await sodium.ready;

    const { encryptedData } = req.body;

    if (!encryptedData) {
      logRegister('Registration failed: Missing encrypted data.');
      return res.status(400).json({ error: 'Missing encrypted data.' });
    }

    // Decrypt the encrypted message
    const privateKey = Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex'));
    const publicKey = sodium.crypto_scalarmult_base(privateKey);
    const keyPair = { publicKey, privateKey };

    const decryptedBytes = sodium.crypto_box_seal_open(
      Uint8Array.from(Buffer.from(encryptedData, 'base64')),
      keyPair
    );

    const decryptedData = JSON.parse(Buffer.from(decryptedBytes).toString());
    const { appSignature, username, password } = decryptedData;

    // Verify the app signature
    if (!appSignature || !(await argon2.verify(HASHED_APP_SIGNATURE, appSignature))) {
      logRegister('Registration failed: Unauthorized app.', { appSignature });
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Check if the username exists
    const userSnapshot = await db.collection('users').where('username', '==', username).get();
    if (!userSnapshot.empty) {
      logRegister('Registration failed: Username already exists.', { username });
      return res.status(400).json({ error: 'Username already exists.' });
    }

    // Hash the password
    const passwordHash = await argon2.hash(password);

    // Store the user in Firestore
    await db.collection('users').add({
      username,
      password_hash: passwordHash,
    });

    logRegister('User registered successfully.', { username });
    return res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    console.error('Error during registration:', error);
    logRegister('Registration failed due to server error.', { error: error.message, stack: error.stack });
    return res.status(500).json({ error: 'Registration failed.', details: error.message });
  }
};
