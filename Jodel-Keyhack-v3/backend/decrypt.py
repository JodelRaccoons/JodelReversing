#! /usr/bin/env python3
#tm
import binascii

#KEY_LOCATION_START = 0xFC00
#KEY_LOCATION_HAYSTACK_SIZE = 0x1000
CLIENT_SECRET_SIZE = 40
CRYPTTABLE_SIZE = 256
SIGNATURE = "a4a8d4d7b09736a0f65596a868cc6fd620920fb0"

def GenerateEncryptionKey():
    encryptionKey = [None] * CRYPTTABLE_SIZE
    sig = SIGNATURE
    signatureLength = len(sig)

    shuffleCounter = 0

    for i in range(CRYPTTABLE_SIZE):
        encryptionKey[i] = i & 0xff

    for shuffleIndex in range(CRYPTTABLE_SIZE):
        encryptionKeyByte = encryptionKey[shuffleIndex] & 0xff
        shuffleCounter += ord(sig[shuffleIndex % signatureLength])
        shuffleCounter += encryptionKeyByte
        shuffleCounter &= 0xff

        encryptionKey[shuffleIndex] = encryptionKey[shuffleCounter]
        encryptionKey[shuffleCounter] = encryptionKeyByte

    return encryptionKey


def decrypt(xorKey):
    #xorKey = b''.join(map(lambda x: int(x, 16).to_bytes(1, 'little'), xorKey))

    clientSecret = [None] * (CLIENT_SECRET_SIZE+1)
    secretCounter = 0

    encryptionKey = GenerateEncryptionKey()

    for secretIndex in range(CLIENT_SECRET_SIZE):
        encryptionKeyByte = encryptionKey[secretIndex + 1] & 0xff
        secretCounter += encryptionKeyByte
        secretCounter &= 0xff

        encryptionKey[secretIndex + 1] = encryptionKey[secretCounter]
        encryptionKey[secretCounter] = encryptionKeyByte
        clientSecret[secretIndex] = (xorKey[secretIndex] ^ encryptionKey[(encryptionKey[secretIndex + 1] + encryptionKeyByte) & 0xff]) & 0xff

    s = ''
    for i in range(CLIENT_SECRET_SIZE):
        s += "%02x" % clientSecret[i]

    return binascii.unhexlify(s)