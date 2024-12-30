const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const { logLogin } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { DateTime } = require('luxon');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;
const HASHED_APP_SIGNATURE = process.env.HASHED_APP_SIGNATURE;

module.exports = async (req, res) => {
  logLogin('Incoming login request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logLogin('Login failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      logLogin('Login failed: Missing encrypted data.');
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
      logLogin('Login failed: Unauthorized app.', { appSignature });
      return res.status(403).json({ error: 'Unauthorized app.' });
    }

    const userData = userDoc.data();
    const usernameHashKey = getHashKey(userData.hash_ver);
    const usernameHash = deterministicUsernameHash(username, usernameHashKey);
    
    const regUserSnapshot = await db.collection('reg_user').where('hashedUsername', '==', usernamehash).get();
    if (regUserSnapshot.empty) {
      logLogin('Login failed: Invalid username.', { username });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const userUUID = regUserSnapshot.docs[0].id;

    const userDoc = await db.collection('users').doc(userUUID).get();
    if (!userDoc.exists) {
      logLogin('Login failed: User data missing.', { username });
      return res.status(500).json({ error: 'User data missing.' });
    }

    if (usernameHash !== userData.u_hash) {
      logLogin('Login failed: Username hash mismatch.', { username });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (!(await argon2.verify(userData.p_hash, password))) {
      logLogin('Login failed: Invalid password.', { username });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Cleanup expired sessions
    await cleanupExpiredSessions(userUUID);

    // Generate new session
    const { key: jwtKey, version: jwtVersion } = getActiveJwtKey();
    const token = jwt.sign({ uuid: userUUID, keyVersion: jwtVersion }, jwtKey, { expiresIn: '1h' });

    const expiryTimestamp = DateTime.now().setZone('Asia/Kolkata').plus({ hours: 1 }).toISO();

    await db.collection('sessions').doc(userUUID).set(
      {
        [userUUID]: {
          token,
          expires_at: expiryTimestamp,
          jwt_version: jwtVersion,
        },
      },
      { merge: true }
    );

    const responseData = {
      message: 'Login successful.',
      token,
      expires_at: expiryTimestamp,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    logLogin('Login successful.', { uuid: userUUID });
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during login:', error);
    logLogin('Login failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
