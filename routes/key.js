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

module.exports = router;