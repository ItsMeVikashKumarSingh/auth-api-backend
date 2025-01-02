const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const jwt = require('jsonwebtoken');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming forgot password request with backup key.');

  if (req.method !== 'POST') {
    console.log('Request failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Request failed: Missing encrypted data.');
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
    const { username, backupKey, clientPublicKey } = decryptedData;

    if (!username || !backupKey) {
      console.log('Request failed: Missing required fields.');
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    // Fetch user UUID via username hash
    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);
      const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();

      if (regUserDoc.exists) {
        userUUID = String(regUserDoc.data().uuid);
        break;
      }
    }

    if (!userUUID) {
      console.log('Request failed: User not found.');
      return res.status(404).json({ error: 'User not found.' });
    }

    // Validate backup key
    const userDocRef = db.collection('users').doc(userUUID);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.log('Request failed: User data missing or corrupted.');
      return res.status(500).json({ error: 'User data missing or corrupted.' });
    }

    const userData = userDoc.data();
    const hashKey = getHashKey(userData.hash_ver);
    const backupKeyHash = deterministicUsernameHash(backupKey, hashKey);

    if (userData.b_code !== backupKeyHash) {
      console.log('Request failed: Invalid backup key.');
      return res.status(401).json({ error: 'Invalid backup key.' });
    }

    // Generate temporary token
    const { key: jwtKey, version: jwtVersion } = getActiveJwtKey();
    const tempToken = jwt.sign(
      { uuid: userUUID, keyVersion: jwtVersion },
      jwtKey,
      { expiresIn: '15m' }
    );

    const responseData = {
      message: 'Backup key validated. Use the token to reset your password.',
      tempToken,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    console.log('Backup key validated successfully.');
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during backup key validation:', error);
    return res.status(500).json({ error: 'Backup key validation failed.', details: error.message });
  }
};
