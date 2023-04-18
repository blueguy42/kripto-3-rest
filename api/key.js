const express = require('express');
const router = express.Router();

const utils = require('../utils');
const crypto = require('../crypto');

router.post('/update', async (req, res) => {
    try {
      const { email } = req.body;
      const response = await utils.key.updateKey(email);
      res.status(201).json({ msg: response[0], publicKey: response[1], privateKey: response[2] });
    } catch (err) {
      console.error(err);
      res.status(500).json({ msg: err.message });
    }
});

router.get('/private', async (req, res) => {
  try {
    const { email } = req.query;
    const response = await utils.key.readPrivateKey(email);
    res.status(200).json({ msg: response[0], privateKey: response[1] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.get('/public', async (req, res) => {
  try {
    const { email } = req.query;
    const response = await utils.key.readPublicKey(email);
    res.status(200).json({ msg: response[0], publicKey: response[1] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/hash', async (req, res) => {
  try {
    const { message } = req.body;
    const response = await crypto.sha3.hash(message);
    res.status(200).json({ hash: response });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/sign', async (req, res) => {
  try {
    const { message, privateKey } = req.body;
    const hashed = await crypto.sha3.hash(message);
    const signature = await crypto.ecdsa.sign(hashed, privateKey);
    const signedText = message + "\n" + "<ds>" + signature + "</ds>";
    res.status(200).json({ signedText: signedText });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/verify', async (req, res) => {
  try {
    const { signedText, publicKey } = req.body;
    const lastNewlineIndex = signedText.lastIndexOf("\n");
    const message = signedText.slice(0, lastNewlineIndex);
    const signature = signedText.slice(lastNewlineIndex + 1).split("<ds>")[1].split("</ds>")[0];
    const hashed = await crypto.sha3.hash(message);
    const response = await crypto.ecdsa.verify(hashed, signature, publicKey);
    res.status(200).json({ valid: response });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.get('/generateKey', async (req, res) => {
  try {
    const privateKey = await crypto.ecdsa.getRandomPrivateKey();
    const publicKey = await crypto.ecdsa.getPublicKey(privateKey);
    res.status(200).json({ privateKey: privateKey, publicKey: publicKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/getPublicKey', async (req, res) => {
  try {
    const { privateKey } = req.body;
    const publicKey = await crypto.ecdsa.getPublicKey(privateKey);
    res.status(200).json({ publicKey: publicKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});


router.post('/encrypt', async (req, res) => {
  try {
    const { plaintext, symmetricKey, iv } = req.body;
    if (!iv) {
      const response = await crypto.omnium.encrypt(plaintext, symmetricKey);
      res.status(200).json({ ciphertext : response });
    } else {
      const response = await crypto.omnium.encrypt(plaintext, symmetricKey, iv);
      res.status(200).json({ ciphertext : response });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/decrypt', async (req, res) => {
  try {
    const { ciphertext, symmetricKey, iv } = req.body;
    if (!iv) {
      const response = await crypto.omnium.decrypt(ciphertext, symmetricKey);
      res.status(200).json({ plaintext : response });
    } else {
      const response = await crypto.omnium.decrypt(ciphertext, symmetricKey, iv);
      res.status(200).json({ plaintext : response });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/sign-encrypt', async (req, res) => {
  try {
    const { plaintext, privateKey, iv, symmetricKey } = req.body;
    const hashed = await crypto.sha3.hash(plaintext);
    const signature = await crypto.ecdsa.sign(hashed, privateKey);
    const signedText = plaintext + '\n' + '<ds>' + signature + '</ds>';
    if (!iv) {
      const response = await crypto.omnium.encrypt(signedText, symmetricKey);
      res.status(200).json({ ciphertext : response});
    } else {
      const response = await crypto.omnium.encrypt(plaintext, symmetricKey, iv);
      res.status(200).json({ ciphertext : response});
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/decrypt-verify', async (req, res) => {
  try {
    const { ciphertext, publicKey, iv, symmetricKey } = req.body;
    let plaintext;
    if (!iv) {
      plaintext = await crypto.omnium.decrypt(ciphertext, symmetricKey);
    } else {
      plaintext = await crypto.omnium.decrypt(ciphertext, symmetricKey, iv);
    }
    const message = plaintext.split("\n")[0];
    const signature = plaintext.split("<ds>")[1].split("</ds>")[0];
    const hashed = await crypto.sha3.hash(message);
    const response = await crypto.ecdsa.verify(hashed, signature, publicKey);
    res.status(200).json({ plaintext: plaintext, valid: response });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});


module.exports = router;