const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const { logRegister } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { generateBackupCode } = require('../utils/generateBackupCode');
const { getActiveHashKey } = require('../utils/keyManager');
const { DateTime } = require('luxon');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;
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
    const { username, password, clientPublicKey } = decryptedData;

    // Hash username and check for existence across all hash versions
    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);

      const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();
      if (regUserDoc.exists) {
        userUUID = regUserDoc.data();
        break;
      }
    }

    if (userUUID) {
      logRegister('Registration failed: Username already exists.', { username });
      return res.status(400).json({ error: 'Username already exists.' });
    }

    // Get the next UUID from reg_user/total
    const totalDoc = await db.collection('reg_user').doc('total').get();
    let nextUUID = 1;

    if (totalDoc.exists) {
      nextUUID = totalDoc.data().lastUUID + 1;
    }

    // Generate deterministic hash for username with the active key
    const { key: activeHashKey } = getActiveHashKey();
    const usernameHash = deterministicUsernameHash(username, activeHashKey);

    // Hash the password and generate a backup code
    const passwordHash = await argon2.hash(password);
    const backupCode = generateBackupCode();
    const backupCodeHash = deterministicUsernameHash(backupCode, activeHashKey);

    const currentTimestamp = DateTime.now().setZone('Asia/Kolkata').toISO();

    // User data to store in users collection
    const userData = {
      u_hash: usernameHash,
      p_hash: passwordHash,
      created_at: currentTimestamp,
      b_code: backupCodeHash,
      bio: DEFAULT_BIO,
      name: DEFAULT_NAME,
      p_pic: DEFAULT_PROFILE_PIC,
      status: DEFAULT_ACCOUNT_STATUS,
    };

    // Store in reg_user and users collections
    await db.collection('reg_user').doc(usernameHash).set({ uuid: nextUUID });
    await db.collection('users').doc(String(nextUUID)).set(userData);

    // Update the `total` document in reg_user
    await db.collection('reg_user').doc('total').set({ lastUUID: nextUUID });

    // Encrypt response with clientPublicKey
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