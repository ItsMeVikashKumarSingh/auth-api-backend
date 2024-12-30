const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const { logRegister } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const { generateBackupCode } = require('../utils/generateBackupCode');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { getActiveHashKey, getHashKey } = require('../utils/keyManager');
const { DateTime } = require('luxon');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

const DEFAULT_BIO = process.env.DEFAULT_BIO;
const DEFAULT_NAME = process.env.DEFAULT_NAME;
const DEFAULT_PROFILE_PIC = process.env.DEFAULT_PROFILE_PIC;
const DEFAULT_ACCOUNT_STATUS = process.env.DEFAULT_ACCOUNT_STATUS;

module.exports = async (req, res) => {
  logRegister('Incoming registration request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logRegister('Registration failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      logRegister('Registration failed: Missing encrypted data.');
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
    const { appSignature, username, password, clientPublicKey } = decryptedData;

    if (!appSignature || !(await argon2.verify(HASHED_APP_SIGNATURE, appSignature))) {
      logRegister('Registration failed: Unauthorized app.', { appSignature });
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    // Fetch all reg_user documents once
    const regUserSnapshot = await db.collection('reg_user').get();
    const regUsers = regUserSnapshot.docs.map(doc => ({
      uuid: doc.id,
      hashedUsername: doc.data().hashedUsername,
      hashVersion: doc.data().hashVersion,
    }));

    // Check if the username exists with any hash version
    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const hashedUsername = deterministicUsernameHash(username, hashKey);

      if (regUsers.some(user => user.hashedUsername === hashedUsername && user.hashVersion === version)) {
        logRegister('Registration failed: Username already exists.', { username });
        return res.status(400).json({ error: 'Username already exists.' });
      }
    }

    // Fetch the current `total` (last UUID assigned) from `reg_user`
    const totalDoc = await db.collection('reg_user').doc('total').get();
    let nextUUID = 1;

    if (totalDoc.exists) {
      nextUUID = totalDoc.data().lastUUID + 1;
    }

    // Hash the username with the active hash key
    const { key: activeHashKey, version: activeHashVersion } = getActiveHashKey();
    const usernameHash = deterministicUsernameHash(username, activeHashKey);

    // Hash the password and generate backup code
    const passwordHash = await argon2.hash(password);
    const backupCode = generateBackupCode();
    const backupCodeHash = deterministicUsernameHash(backupCode, activeHashKey);

    const currentTimestamp = DateTime.now().setZone('Asia/Kolkata').toISO();

    // Store user data in Firestore
    const userData = {
      u_hash: usernameHash,
      hash_ver: activeHashVersion,
      p_hash: passwordHash,
      b_code: backupCodeHash,
      created_at: currentTimestamp,
      last_login: null,
      bio: DEFAULT_BIO,
      name: DEFAULT_NAME,
      p_pic: DEFAULT_PROFILE_PIC,
      status: DEFAULT_ACCOUNT_STATUS,
    };

    await db.collection('reg_user').doc(String(nextUUID)).set({
      hashedUsername: usernameHash,
      hashVersion: activeHashVersion,
    });
    await db.collection('users').doc(String(nextUUID)).set(userData);

    // Update the `total` document in `reg_user` with the new last UUID
    await db.collection('reg_user').doc('total').set({ lastUUID: nextUUID });

    const responseData = {
      message: 'User registered successfully.',
      backupCode,
      uuid: nextUUID,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    logRegister('User registered successfully.', { uuid: nextUUID });
    return res.status(201).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during registration:', error);
    logRegister('Registration failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Registration failed.', details: error.message });
  }
};
