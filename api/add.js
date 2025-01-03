const db = require('../utils/firebaseAdmin');
const { logProtected } = require('../utils/logger');
require('dotenv').config();

module.exports = async (req, res) => {
  console.log('Incoming request to add predefined questions.');

  if (req.method !== 'POST') {
    console.log('Failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const predefinedQuestions = [
      "What was your first pet's name?",
      "What is the name of the town where you were born?",
      "What was your childhood nickname?",
      "What is your mother's maiden name?",
      "What is the name of your first school?",
      "What was the model of your first car?",
      "What is your favorite movie?",
      "Who was your childhood hero?",
      "What is your favorite sports team?",
      "What was the name of your first teacher?",
      "What is your dream job?",
      "What was the name of your first crush?",
      "What is your favorite book?",
      "What is the name of your best friend?",
      "What was the name of your first boss?",
      "What is the name of the street you grew up on?",
      "What is your favorite hobby?",
      "What was the name of your first roommate?",
      "What is your father's middle name?",
      "What is the name of your favorite childhood toy?",
      "What is your favorite holiday destination?",
      "What is your favorite cuisine?",
      "What is the name of your favorite teacher?",
      "What is your favorite season?",
      "What is your favorite color?",
      "What is the name of your favorite relative?",
      "What was the name of your first job?",
      "What is your favorite music genre?",
      "What is your favorite artist?",
      "What was your first phone model?"
    ];

    // Check if questions already exist
    const questionsRef = db.collection('ver_questions');
    const questionsDoc = await questionsRef.doc('questions').get();

    if (questionsDoc.exists) {
      console.log('Predefined questions already exist.');
      return res.status(400).json({ error: 'Questions already added.' });
    }

    // Add predefined questions to Firestore
    await questionsRef.doc('questions').set({ questions: predefinedQuestions });

    console.log('Predefined questions added successfully.');
    return res.status(201).json({ message: 'Predefined questions added successfully.' });
  } catch (error) {
    console.error('Error adding predefined questions:', error.message);
    return res.status(500).json({ error: 'Failed to add predefined questions.', details: error.message });
  }
};
