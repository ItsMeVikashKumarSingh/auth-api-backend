const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const { logLogin } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { DateTime } = require('luxon');
const crypto = require('crypto');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;
const APP_SIGNATURE = process.env.APP_SIGNATURE;

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

    // Match plain text appSignature
if (appSignature !== APP_SIGNATURE) {
  logLogin('Login failed: Unauthorized app.', { appSignature });

  // Fetch user data using username hash iteratively
  const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
  let userUUID = null;

  for (const [version, hashKey] of Object.entries(hashKeys)) {
    const usernameHash = deterministicUsernameHash(username, hashKey);

    const regUserSnapshot = await db
      .collection('reg_user')
      .where('hashedUsername', '==', usernameHash)
      .where('hashVersion', '==', version)
      .get();

    if (!regUserSnapshot.empty) {
      userUUID = regUserSnapshot.docs[0].id;
      break;
    }
  }

  if (!userUUID) {
    return res.status(401).json({ error: 'Invalid username or unauthorized app.' });
  }

  // Fetch user document
  const userDocRef = db.collection('users').doc(userUUID);
  const userDoc = await userDocRef.get();

  if (!userDoc.exists) {
    return res.status(500).json({ error: 'User data missing.' });
  }

  const userData = userDoc.data();

  const currentTime = DateTime.now().setZone('Asia/Kolkata');
  const lastAttemptTime = userData.lastAttemptTime ? DateTime.fromISO(userData.lastAttemptTime) : null;
  const attempts = userData.attempts || 0;
  let warnings = userData.warnings || 0;

  // Handle login attempts
  if (lastAttemptTime && currentTime.diff(lastAttemptTime, 'minutes').minutes <= 30) {
    if (attempts >= 3) {
      const retryAfter = lastAttemptTime.plus({ minutes: 30 }).toFormat('hh:mm a');
      logLogin('Login failed: Too many attempts.', { uuid: userUUID, attempts, retryAfter });
      return res.status(429).json({
        error: `Too many attempts. Please try again after ${retryAfter} IST.`,
      });
    }
  } else {
    // Reset attempts if more than 30 minutes have passed
    await userDocRef.update({
      attempts: 1,
      lastAttemptTime: currentTime.toISO(),
    });
  }

  // Increment warnings and attempts
  warnings += 1;
  const updatedAttempts = attempts + 1;

  // Ban account if warnings exceed threshold
  if (warnings >= 5) {
    await userDocRef.update({
      status: 'banned',
      warnings,
      attempts: updatedAttempts,
      lastAttemptTime: currentTime.toISO(),
    });
    logLogin('Login failed: Account banned due to repeated invalid attempts.', { uuid: userUUID });
    return res.status(403).json({ error: 'Account has been banned due to repeated invalid attempts.' });
  }

  // Update warnings, attempts, and last attempt time
  await userDocRef.update({
    warnings,
    attempts: updatedAttempts,
    lastAttemptTime: currentTime.toISO(),
  });

  logLogin('Login failed: Unauthorized app.', { uuid: userUUID, warnings, attempts: updatedAttempts });
  return res.status(403).json({ error: 'Unauthorized app.', warnings, attempts: updatedAttempts });
}

    // Reset warnings and attempts on successful login
    await userDocRef.update({ warnings: 0, attempts: 0 });

    // Update last login
    const currentTimestamp = currentTime.toISO();
    await userDocRef.update({ last_login: currentTimestamp });

    // Cleanup expired sessions
    await cleanupExpiredSessions(userUUID);

    // Generate new session
    const sessionId = crypto.randomUUID();
    const { key: jwtKey, version: jwtVersion } = getActiveJwtKey();
    const token = jwt.sign(
      { uuid: userUUID, sessionId, keyVersion: jwtVersion },
      jwtKey,
      { expiresIn: '1h' }
    );

    const expiryTimestamp = currentTime.plus({ hours: 1 }).toISO();

    const sessionsRef = db.collection('sessions').doc(userUUID);
    const sessionsDoc = await sessionsRef.get();

    const updatedSessions = sessionsDoc.exists ? sessionsDoc.data() : {};
    updatedSessions[sessionId] = {
      token,
      expires_at: expiryTimestamp,
      jwt_version: jwtVersion,
    };

    await sessionsRef.set(updatedSessions);

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

    logLogin('Login successful.', { uuid: userUUID, sessionId });
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during login:', error);
    logLogin('Login failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
