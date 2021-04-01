import random
import sys
from hashlib import sha256

from Crypto.PublicKey import RSA


def generateRSAKeys(num_Bits):
    key_Pair = RSA.generate(num_Bits)

    return key_Pair


def checkOneNonce(num_Zeros_Needed, nonce):
    nByte = bytes(str(nonce), 'utf-8')
    hashVal = int.from_bytes(sha256(nByte).digest(), byteorder='big')

    hashBin = bin(hashVal)
    hashLSB = int(hashBin[-num_Zeros_Needed:])

    if hashLSB == 0:
        print('nRand:', nonce, '; hash_lsb:', hashLSB)
    validity = (hashLSB == 0)
    return validity


def digitalSignRSA(msg, keyPairRSA):
    hash_Value = int.from_bytes(sha256(msg).digest(), byteorder='big')
    signature = pow(hash_Value, keyPairRSA.d, keyPairRSA.n)

    return hash_Value, signature


def digitalVerifyRSA(msg, keyPairRSA, signature):
    hash_Value = int.from_bytes(sha256(msg).digest(), byteorder='big')
    hashFromSignature = pow(signature, keyPairRSA.e, keyPairRSA.n)

    validity = (hash_Value == hashFromSignature)
    return validity


if __name__ == '__main__':
    num_argv = len(sys.argv)
    if num_argv == 1:
        numBits = 1024
        keyPair = generateRSAKeys(numBits)
        print("Public key:  n={", hex(keyPair.n), "}, e={", hex(keyPair.e), "})")
        print('  ')
        print("Private key: n={", hex(keyPair.n), "}, d={", hex(keyPair.d), "})")
        print('  ')

        numZerosNeeded = 5
        while True:
            nonce = random.randint(0, 1000000)
            validNonce = checkOneNonce(numZerosNeeded, nonce)
            if validNonce:
                break

        msg = bytes(str(nonce) + ' ' + '1903165', 'utf-8')
        (hashValue, signature) = digitalSignRSA(msg, keyPair)
        print("Hash value of message:", hashValue)
        print("Signature:", hex(signature))
        print('  ')
        print("msg of nonce and number:", msg)

        print('######################################################################')
        print('After message has been tampered with')
        msgTampered = bytes('A message for signing (tampered)', 'utf-8')
        validity = digitalVerifyRSA(msgTampered, keyPair, signature)
        print("Signature validity:", validity)
        print('######################################################################')
        print('  ')

        validity = digitalVerifyRSA(msg, keyPair, signature)
        print("Signature validity:", validity)
        print('  ')
        print('The validity of this nonce ', nonce, ' is:', validNonce)
        print('====================================================')
    else:
        print('+++Please input the python file you want to read')
        exit()
