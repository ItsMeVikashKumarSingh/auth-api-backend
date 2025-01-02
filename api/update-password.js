const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { getHashKey } = require('../utils/keyManager');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming password update request.');

  if (req.method !== 'POST') {
    console.log('Update failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Update failed: Missing encrypted data.');
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
    const { username, newPassword } = decryptedData;

    if (!username || !newPassword) {
      console.log('Update failed: Missing username or new password.');
      return res.status(400).json({ error: 'Missing username or new password.' });
    }

    // Hash username to get UUID
    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);
      const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();

      if (regUserDoc.exists) {
        userUUID = String(regUserDoc.data().uuid); // Ensure UUID is a string
        break;
      }
    }

    if (!userUUID) {
      console.log('Update failed: User not found.');
      return res.status(404).json({ error: 'User not found.' });
    }

    // Update password
    const userDocRef = db.collection('users').doc(userUUID);
    const passwordHash = await argon2.hash(newPassword);
    await userDocRef.update({ p_hash: passwordHash });

    console.log('Password updated successfully.');
    return res.status(200).json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Error during password update:', error);
    return res.status(500).json({ error: 'Password update failed.', details: error.message });
  }
};
