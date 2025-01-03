const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const argon2 = require('argon2');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming request to store user-selected security questions.');

  if (req.method !== 'POST') {
    console.log('Failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Failed: Missing encrypted data.');
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
    const { uuid, selectedQuestions, answers } = decryptedData;

    console.log('Decrypted request data:', { uuid, selectedQuestions });

    if (!uuid || typeof uuid !== 'string' || uuid.trim() === '') {
      console.log('Failed: Missing or invalid UUID.');
      return res.status(400).json({ error: 'Missing or invalid UUID.' });
    }

    if (!Array.isArray(selectedQuestions) || selectedQuestions.length !== 5) {
      console.log('Failed: User must select exactly 5 questions.');
      return res.status(400).json({ error: 'User must select exactly 5 questions.' });
    }

    if (!Array.isArray(answers) || answers.length !== 5) {
      console.log('Failed: User must provide answers for all 5 questions.');
      return res.status(400).json({ error: 'User must provide answers for all 5 questions.' });
    }

    // Hash answers using Argon2
    const hashedAnswers = await Promise.all(answers.map(answer => argon2.hash(answer)));

    const userQuestionsData = selectedQuestions.map((questionId, index) => ({
      questionId,
      answerHash: hashedAnswers[index],
    }));

    // Store in Firestore
    await db.collection('user_questions').doc(uuid).set({ questions: userQuestionsData });

    console.log('User-selected security questions stored successfully.');
    return res.status(201).json({ message: 'Security questions stored successfully.' });
  } catch (error) {
    console.error('Error storing user questions:', error.message);
    return res.status(500).json({ error: 'Failed to store user questions.', details: error.message });
  }
};
