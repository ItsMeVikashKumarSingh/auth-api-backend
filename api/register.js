const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const { logRegister } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX; // Private key in hex format
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;  // Public key in hex format
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  logRegister('Incoming registration request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logRegister('Registration failed: Method not allowed.');
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

    // Validate hex strings
    if (!/^[0-9a-fA-F]{64}$/.test(PRIVATE_KEY_HEX) || !/^[0-9a-fA-F]{64}$/.test(PUBLIC_KEY_HEX)) {
      console.error('PRIVATE_KEY_HEX or PUBLIC_KEY_HEX is not a valid 64-character hexadecimal string.');
      return res.status(500).json({ error: 'Invalid key format.' });
    }

    const { encryptedData } = req.body;

    if (!encryptedData) {
      logRegister('Registration failed: Missing encrypted data.');
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