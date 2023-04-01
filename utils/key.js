const { db } = require('./firebase');
const crypto = require('../crypto');

async function updateKey(email) {
  try {
    // Generate public and private key
    const { public_key, private_key } = await crypto.key.createKey(email);

    // Check if document with name 'email' exists
    const docRef = await db.collection('keys').doc(email);
    const query = await docRef.get();
    if (query.exists) {
      // If exist, update public and private key
      await docRef.update({
        public_key,
        private_key
      });
      return [`Key updated with email: ${email}`, public_key, private_key];
    } else {
      // If not exist, add a new document
      const docRef = await db.collection('keys').doc(email).set({
        public_key,
        private_key
      });
      return [`Key added with email: ${email}`, public_key, private_key];
    }
  } catch (err) {
    console.error(err);
    throw new Error(err.message);
  }
}

async function readPrivateKey(email) {
  try {
    const docRef = await db.collection('keys').doc(email);
    const query = await docRef.get();
    if (!query.exists) {
      throw new Error(`Key of email ${email} does not exist`);
    }
    const data = query.data();
    return [`Private key of email ${email} successfully read`, data.private_key];
  } catch (err) {
    console.error(err);
    throw new Error(err.message);
  }
}

async function readPublicKey(email) {
  try {
    const docRef = await db.collection('keys').doc(email);
    const query = await docRef.get();
    if (!query.exists) {
      throw new Error(`Key of email ${email} does not exist`);
    }
    const data = query.data();
    return [`Public key of email ${email} successfully read`, data.public_key];
  } catch (err) {
    console.error(err);
    throw new Error(err.message);
  }
}

module.exports = {
  updateKey,
  readPrivateKey,
  readPublicKey
};