# -*- coding: utf-8 -*-
"""
Created on Thu Feb 29 17:29:19 2024
@author: Nir Betesh, Almog Khaikin and Ofek Malka
"""
from rc6 import *
from blind_rsa import *
from diffie_hellman import *
from sys import exit

def main():
    print('Alice generates keypair for Diffie-Hellman')
    dh1 = DiffieHellman()
    print(f'Alice\'s public key: {dh1.publicKey}')
    print(f'Alice\'s private key: {dh1.privateKey}')

    print('\nBob generates keypair for Diffie-Hellman')
    dh2 = DiffieHellman()
    print(f'Bob\'s public key: {dh2.publicKey}')
    print(f'Bob\'s private key: {dh2.privateKey}')

    print('\nAlice computes shared key with Bob\'s public key')
    dh1.genKey(dh2.publicKey)
    print('Bob computes shared key with Alice\'s public key')
    dh2.genKey(dh1.publicKey)

    sharedKey1 = dh1.getKey()
    print(f'Alice\'s shared key: 0x{sharedKey1.hex()}')
    sharedKey2 = dh2.getKey()
    print(f'Bob\'s shared key: 0x{sharedKey2.hex()}\n')

    print('Alice computes RC6 key schedule')
    internal_keys1 = generateKey(sharedKey1)
    print('Bob computes RC6 key schedule\n')
    internal_keys2 = generateKey(sharedKey2)

    print('Signer provides public RSA key (Computed once ahead of time in reality)')
    public_key, N = init_key_pair()
    print(f'Public RSA key: ({public_key}, {N})\n')

    while True:
        message = input('Please enter the message that Alice is sending (Q to quit): ')
        if message == 'q':
            exit('Exiting...')
        print('Alice encrypts the message')
        encrypted_message = encrypt(message, internal_keys1)
        print(f'Encrypted message: 0x{encrypted_message.encode(encoding="raw_unicode_escape").hex()}\n')
        print('Alice hashes message for signing')
        hashed = message_hash(encrypted_message)
        print(f'Hashed message: {hashed}\n')
        print('Alice blinds message before sending it to signer')
        blinded, coprime = blind_message(hashed, public_key, N)
        print(f'Blinded message: {blinded}\n')
        print('Signer signs the message')
        signed = sign_message(blinded)
        print(f'Signed message: {signed}\n')
        print('Alice unblinds the signed message')
        unblinded = unblind_message(signed, coprime, N)
        print(f'Unblinded message: {unblinded}\n')
        
        print('Alice validates the signature: ', end='')
        if not validate_signature(encrypted_message, unblinded):
            exit('Invalid signature returned by signer')
        
        print('Validated')

        print('Alice sends the encrypted message and the digital signature to Bob')

        print('Bob validates the digital signature')
        validated = validate_signature(encrypted_message, unblinded)
        if validated:
            print('The message was successfully validated!')
        else:
            print('The message failed validation!')
            continue

        print('Bob decrypts the message')
        d = decrypt(encrypted_message, internal_keys2)
        print(f'The message that Bob received: {d}\n')

        print('\n'*4)


if __name__ == '__main__':
    main()
