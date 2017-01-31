#!/usr/bin/python3

"""
restic repository pack file decryptor in Python

Minimal implementation of decryption of individual restic repository pack files.
"""

from binascii import hexlify
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util import Counter
import json
import base64
import scrypt

def decrypt(masterkey, data):
    """Decrypt ciphertext with master key

    Master key and data must be of 'bytes' type.
    Decryption with AES-256 CTR using IV from first 16 bytes,
    and discarding last 16 bytes."""

    iv = data[:16]
    ciphertext = data[16:-16]
    mac = data[-16:]

    iv_int = int.from_bytes(iv, byteorder="big")

    crypto = AES.new(masterkey, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv_int, little_endian=False))
    return crypto.decrypt(ciphertext)

def get_masterkey(keyfile, password):
    """Decrypt masterkey from key file"""

    with open(keyfile, "rb") as f:
        keyfile_json = json.loads(str(f.read(), "utf-8"))
    salt = keyfile_json['salt']
    data = keyfile_json['data']

    # Hash password with scrypt
    key = scrypt.hash(password, base64.b64decode(salt), N=16384, r=8, p=1)

    # Decode master key from data
    masterkey_data = decrypt(key[:32], base64.b64decode(data))
    masterkey_json = json.loads(str(masterkey_data, 'utf-8'))
    masterkey = masterkey_json['encrypt']
    return base64.b64decode(masterkey)

def decrypt_packfile(masterkey, filename):
    """Decrypt all content of a pack file and return json"""

    with open(filename, "rb") as f:
        data = f.read()

    header_length = int.from_bytes(data[-4:], byteorder="little")
    header = decrypt(masterkey, data[-4-header_length:-4])

    number_of_blobs = len(header) // 37
    blobs = []
    data_offset = 0
    for i in range(number_of_blobs):
        header_offset = 37 * i
        blob = {}
        blob['type'] = "tree" if header[header_offset] else "data"
        blob['offset'] = data_offset
        blob['length'] = int.from_bytes(header[1 + header_offset:5 + header_offset], byteorder="little")
        blob['id'] = hexlify(header[5 + header_offset:32+5 + header_offset])
        blob['decrypted_content'] = decrypt(masterkey, data[blob['offset']:blob['offset']+blob['length']])
        blobs.append(blob)
        data_offset += blob['length']
    return blobs

def decrypt_config_index_snapshot(masterkey, filename):
    """Decrypt config, indexes, or snapshots"""

    with open(filename, "rb") as f:
        return json.loads(str(decrypt(masterkey, f.read()), "utf-8"))

def test_simple_decrypt():
    """Test decryption with test data from crypto_int_test.go"""

    data_bytes = unhexlify("69fb41c62d12def4593bd71757138606338f621aeaeb39da0fe4f99233f8037a54ea63338a813bcf3f75d8c3cc75dddf8750")
    key = bytes([0x30, 0x3e, 0x86, 0x87, 0xb1, 0xd7, 0xdb, 0x18, 0x42, 0x1b, 0xdc, 0x6b, 0xb8, 0x58, 0x8c, 0xca, 0xda, 0xc4, 0xd5, 0x9e, 0xe8, 0x7b, 0x8f, 0xf7, 0x0c, 0x44, 0xe6, 0x35, 0x79, 0x0c, 0xaf, 0xef])
    res = decrypt(key, data_bytes)
    if res != b'Dies ist ein Test!':
        raise Exception("Decryption failed")

if __name__=="__main__":

    test_simple_decrypt() # simple test

    # password = b"test"
    # masterkey = get_masterkey("repo/keys/da2d94d8ef4aa70febb2a248c5d8511f30f0ed4e21abd83fed8eba036c90be8e", password)
    # print(decrypt_config_index_snapshot(masterkey, "repo/snapshots/ae73930431bb74f0589ac462339bb1c1b48040cda208cfa2d59978c8575a736d"))
    # print(decrypt_config_index_snapshot(masterkey, "repo/config"))
    # print(decrypt_config_index_snapshot(masterkey, "repo/index/e6b2f85cb46d978dd841d2dd183a21300081992259c265bcb2500e31a26651a4"))
    # print(decrypt_packfile(masterkey, "repo/data/96/96f1f07039a147e0e3bbcf99a5b3a86119769db291a226dc28db51583c655243"))
