const db = require('../utils/firebaseAdmin');
const argon2 = require('argon2');
const sodium = require('libsodium-wrappers');
const jwt = require('jsonwebtoken');
const { getActiveJwtKey } = require('../utils/keyManager');
const { logProtected } = require('../utils/logger');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming forgot password request using security questions.');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Security questions validation failed: Missing encrypted data.');
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
    const { username, answers, clientPublicKey } = decryptedData;

    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);
      const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();

      if (regUserDoc.exists) {
        userUUID = regUserDoc.data().uuid;
        break;
      }
    }

    if (!userUUID) {
      console.log('Validation failed: User not found.');
      return res.status(404).json({ error: 'User not found.' });
    }

    const userQuestionsDocRef = db.collection('user_questions').doc(String(userUUID));
    const userQuestionsDoc = await userQuestionsDocRef.get();

    if (!userQuestionsDoc.exists) {
      console.log('Validation failed: Security questions not set.');
      return res.status(404).json({ error: 'Security questions not set.' });
    }

    const userQuestionsData = userQuestionsDoc.data();

    // Verify each answer
    for (let i = 0; i < answers.length; i++) {
      const userAnswer = userQuestionsData[`q${i + 1}_hash`];
      if (!(await argon2.verify(userAnswer, answers[i]))) {
        console.log('Validation failed: Incorrect answer to security question.', { question: `q${i + 1}` });
        return res.status(401).json({ error: 'Incorrect answers to security questions.' });
      }
    }

    const { key: jwtKey, version: jwtVersion } = getActiveJwtKey();
    const tempToken = jwt.sign(
      { uuid: userUUID, keyVersion: jwtVersion },
      jwtKey,
      { expiresIn: '15m' }
    );

    const responseData = {
      message: 'Security questions validated. Use the token to reset your password.',
      tempToken,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    logProtected('Security questions validated successfully.', { uuid: userUUID });
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during security questions validation:', error);
    logProtected('Security questions validation failed.', { error: error.message });
    return res.status(500).json({ error: 'Validation failed.', details: error.message });
  }
};
