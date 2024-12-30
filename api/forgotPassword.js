const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const { logForgotPassword } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const { generateBackupCode } = require('../utils/generateBackupCode');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { getHashKey, getActiveHashKey } = require('../utils/keyManager');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  logForgotPassword('Incoming forgot password request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logForgotPassword('Forgot password failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      logForgotPassword('Forgot password failed: Missing encrypted data.');
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
    const { appSignature, backupCode, newPassword, newUsername = null, clientPublicKey } = decryptedData;

    if (!appSignature || !(await argon2.verify(HASHED_APP_SIGNATURE, appSignature))) {
      logForgotPassword('Forgot password failed: Unauthorized app.', { appSignature });
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Fetch all `users` documents to validate backup code
    const usersSnapshot = await db.collection('users').get();
    const users = usersSnapshot.docs.map(doc => ({
      uuid: doc.id,
      hashedBackupCode: doc.data().b_code,
      hashVersion: doc.data().hash_ver,
    }));

    let userUUID = null;
    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');

    // Check if the backup code matches any user
    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const backupCodeHash = deterministicUsernameHash(backupCode, hashKey);

      const matchedUser = users.find(
        user => user.hashedBackupCode === backupCodeHash && user.hashVersion === version
      );

      if (matchedUser) {
        userUUID = matchedUser.uuid;
        break;
      }
    }

    if (!userUUID) {
      logForgotPassword('Forgot password failed: Invalid backup code.');
      return res.status(401).json({ error: 'Invalid backup code.' });
    }

    const updates = {};

    if (newUsername) {
      const { key: activeHashKey, version: activeHashVersion } = getActiveHashKey();
      const newUsernameHash = deterministicUsernameHash(newUsername, activeHashKey);
      updates.u_hash = newUsernameHash;
      updates.hash_ver = activeHashVersion;
    }

    if (newPassword) {
      updates.p_hash = await argon2.hash(newPassword);
    }

    const newBackupCode = generateBackupCode();
    const activeHashKey = getActiveHashKey().key;
    updates.b_code = deterministicUsernameHash(newBackupCode, activeHashKey);

    await db.collection('users').doc(userUUID).update(updates);

    const responseData = {
      message: 'Credentials updated successfully.',
      newBackupCode,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    logForgotPassword('Credentials updated successfully.', { uuid: userUUID });
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during forgot password:', error);
    logForgotPassword('Forgot password failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Forgot password failed.', details: error.message });
  }
};
