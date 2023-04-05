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
    const response = await crypto.ecdsa.sign(hashed, privateKey);
    res.status(200).json({ signature: response });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});

router.post('/verify', async (req, res) => {
  try {
    const { message, signature, publicKey } = req.body;
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

router.get('/test', async (req, res) => {
  try {
    const bn = require('bn.js');
    function uint256(x, base) {
      return new bn(x, base)
    }
    const pubX = uint256('5b75fd5f49e78191a45e1c9438644fe5d065ea98920c63e9eef86e151e99b809', 16)
    const pubY = uint256('4eef2a826f1e6d13a4dde4e54800e8d282a2089a873072002e0a3a21eae5763a', 16)
    const pk = pubX.toString(16).padStart(64, '0') + pubY.toString(16).padStart(64, '0');
    const sig = await crypto.ecdsa.sign("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
          "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    const valid = await crypto.ecdsa.verify("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", sig, pk )
    console.log(valid)
    res.status(200).json({ valid: valid });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: err.message });
  }
});


module.exports = router;