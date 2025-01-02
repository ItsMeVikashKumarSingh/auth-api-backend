const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const speakeasy = require('speakeasy');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming TOTP validation request.');

  if (req.method !== 'POST') {
    console.log('Validation failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Validation failed: Missing encrypted data.');
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
    const { uuid, totp } = decryptedData;

    if (!uuid || !totp) {
      console.log('Validation failed: Missing UUID or TOTP.');
      return res.status(400).json({ error: 'Missing UUID or TOTP.' });
    }

    const userUUID = String(uuid);

    // Fetch authenticator secret
    const userDocRef = db.collection('users').doc(userUUID);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.log('Validation failed: User not found.');
      return res.status(404).json({ error: 'User not found.' });
    }

    const userData = userDoc.data();

    if (!userData.authenticatorSecret) {
      console.log('Validation failed: Authenticator not enabled.');
      return res.status(400).json({ error: 'Authenticator not enabled.' });
    }

    // Validate TOTP
    const isValid = speakeasy.totp.verify({
      secret: userData.authenticatorSecret,
      encoding: 'base32',
      token: totp,
    });

    if (!isValid) {
      console.log('Validation failed: Invalid TOTP.');
      return res.status(401).json({ error: 'Invalid TOTP.' });
    }

    console.log('TOTP validated successfully.');
    return res.status(200).json({ message: 'TOTP validated successfully.' });
  } catch (error) {
    console.error('Error during TOTP validation:', error);
    return res.status(500).json({ error: 'TOTP validation failed.', details: error.message });
  }
};
