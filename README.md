# SECURE SMS EXCHANGE
## Overview
This project implements a secure SMS exchange system using cryptographic protocols to ensure privacy and security in digital communications. The system incorporates the Diffie-Hellman key exchange for generating a shared secret key, RC6 for encryption, and a Blind RSA signature for message authenticity.

## Features
**Diffie-Hellman Key Exchange:** Establishes a shared secret key between two parties without prior communication, secure against the discrete logarithm problem.

**RC6 Encryption:** A symmetric key block cipher that encrypts and decrypts messages using a shared secret key.

**Blind RSA Signature:** Enhances privacy by allowing messages to be signed without revealing their content to the signer.


## Installation
```bash
git clone https://github.com/Nir-betesh/Crypto_Project
cd Crypto_Project-main
pip install -r requirements.txt
```

## Usage
To run the SMS simulation
```bash
python main.py
```
Follow the on-screen instructions to simulate sending and receiving encrypted messages.

## Authors
Ofek Malka

Almog Khaikin

Nir Betesh

## License
This project is licensed under the MIT License - see the LICENSE file for details.
