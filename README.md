# Kripto3 REST API

This repository contains the source code for the Kripto3 API, an Express backend that provides cryptographic services for block cipher encryption (using <a href="https://github.com/Putriliza/Kripto-2">Omnium Cipher</a>) and digital signature (using ECDSA and Keccak or SHA-3).

The program was created to fulfill **IF4020 Cryptography: Major Assignment 3** in Semester II 2022/2023.

# Table of Contents
* [How to Run the Program](#how-to-run-the-program)
* [Routes](#routes)
* [Contributors](#contributors)

# How to Run the Program

The server is deployed at https://kripto3-api.afanhandoyo.com/.

You can also choose to run the program locally.

To run the program, follow these steps:

1. Clone this repository to your local machine.
2. Install the required dependencies by running `npm install` in the root directory of the cloned repository.
3. Start the server by running `npm run start` in the root directory of the cloned repository.
4. The server will start running on http://localhost:3000/ by default.

# Routes

The following routes are used:

## GET '/api/key/generateKey'

Response:

```json
{
    "privateKey": "string",
    "publicKey": "string"
}
```

Generates a private and public key pair for digital signature. The private and public keys are returned as strings.

## POST '/api/key/sign'
Body:

```json
{
    "message": "string",
    "privateKey": "string"
}
```

Response:

```json
{
    "signedText": "string"
}
```
Signs a message using the private key provided in the request body. The signed message is returned as a string.

## POST '/api/key/verify'

Body:

```json
{
  "signedText": "string",
  "publicKey": "string"
}
```

Response:

```json
{
  "valid": true
}
```
Verifies the signature of a signed message using the public key provided in the request body. Returns a boolean indicating whether the signature is valid or not.

## POST '/api/key/encrypt'

Body:

```json
{
  "plaintext": "string",
  "symmetricKey": "string"
}
```
Response:

```json
{
  "ciphertext": "string"
}
```
Encrypts a plaintext message using a symmetric key provided in the request body. Returns the ciphertext as a string.

## POST '/api/key/decrypt'

Body:

```json
{
  "ciphertext": "string",
  "symmetricKey": "string"
}
```

Response:

```json
{
  "plaintext": "string"
}
```

Decrypts a ciphertext message using a symmetric key provided in the request body. Returns the plaintext as a string.

# Contributors
This project was developed by:

- <a href="https://www.linkedin.com/in/ahmad-alfani-handoyo/">13520023 Ahmad Alfani Handoyo</a>
- <a href="https://www.linkedin.com/in/putri-nurhaliza/">13520066 Putri Nurhaliza</a>
- <a href="https://www.linkedin.com/in/ubaidillah-ariq-prathama-03535a1ba/">13520085 Ubaidillah Ariq Prathama</a>
