const argon2 = require('argon2');
const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const { logProtected } = require('../utils/logger');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming request to store security questions.');

  if (req.method !== 'POST') {
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
    const { uuid, questions, answers, clientPublicKey } = decryptedData;

    if (!uuid || !Array.isArray(questions) || !Array.isArray(answers) || questions.length !== 5 || answers.length !== 5) {
      console.log('Request failed: Invalid data format.');
      return res.status(400).json({ error: 'Invalid data format.' });
    }

    // Hash each answer
    const hashedAnswers = {};
    for (let i = 0; i < answers.length; i++) {
      const answerHash = await argon2.hash(answers[i]);
      hashedAnswers[`q${i + 1}_hash`] = answerHash;
    }

    // Store security questions and answers
    const userQuestionsDocRef = db.collection('user_questions').doc(String(uuid));
    const dataToStore = {
      uuid: uuid,
      ...hashedAnswers,
      questions: questions, // Questions stored in plaintext for retrieval
    };

    await userQuestionsDocRef.set(dataToStore);

    const responseData = {
      message: 'Security questions stored successfully.',
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    logProtected('Security questions stored successfully.', { uuid });
    return res.status(201).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error storing security questions:', error);
    logProtected('Failed to store security questions.', { error: error.message });
    return res.status(500).json({ error: 'Failed to store security questions.', details: error.message });
  }
};
