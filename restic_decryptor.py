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
import os

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

# repository/key.go
def get_masterkey(keyfile, password):
    """Decrypt masterkey from key file"""

    with open(keyfile, "rb") as f:
        keyfile_json = json.loads(str(f.read(), "utf-8"))
    if keyfile_json.get("kdf","scrypt") != "scrypt":
        raise Exception("only scrypt KDF supported")
    salt = keyfile_json['salt']
    data = keyfile_json['data']
    # Hash password with scrypt
    key = scrypt.hash(password, base64.b64decode(salt), N=keyfile_json.get("N",16384), r=keyfile_json.get("r",8), p=keyfile_json.get("p",1))
 
    # Decode master key from data
    masterkey_data = decrypt(key[:32], base64.b64decode(data))
    masterkey_json = json.loads(str(masterkey_data, 'utf-8'))
    masterkey = masterkey_json['encrypt']
    return base64.b64decode(masterkey)

def decrypt_packfile(masterkey, filename, decrypt_content=True):
    """Decrypt all content of a pack file and return dict"""

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
        if decrypt_content:
            blob['decrypted_content'] = decrypt(masterkey, data[blob['offset']:blob['offset']+blob['length']])
        blobs.append(blob)
        data_offset += blob['length']
    return blobs, header_length

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

def get_pack_content_lengths(masterkey, filename):
    """Count lengths of pack file contents by type"""

    header_len = 0
    tree_len = 0
    data_len = 0
    tree_num = 0
    data_num = 0
    blobs, header_len = decrypt_packfile(masterkey, filename, decrypt_content=False)
    for i in blobs:
        if i['type'] == "tree":
            tree_len += i['length']
            tree_num += 1
        elif i['type'] == "data":
            data_len += i['length']
            data_num += 1
        else:
            raise Exception()
    return {"header_len": header_len,
            "tree_len": tree_len,
            "data_len": data_len,
            "tree_num": tree_num,
            "data_num": data_num,
            }

def get_all_pack_content_lengths(masterkey, path):
    """Summarize all pack file content lengths by type"""

    header_len = 0
    tree_len = 0
    data_len = 0
    tree_num = 0
    data_num = 0
    pack_num = 0
    for dirname, dirnames, filenames in os.walk(path):
        for filename in filenames:
            res = get_pack_content_lengths(masterkey, os.path.join(dirname, filename))
            header_len += res["header_len"]
            tree_len += res["tree_len"]
            data_len += res["data_len"]
            tree_num += res["tree_num"]
            data_num += res["data_num"]
            pack_num += 1
        print("---- dir: {} ----".format(dirname))
        print("header_length:{: >15}\ntree_length:  {: >15}\ndata_length:  {: >15}".format(header_len, tree_len, data_len))
        print("treeblobs:    {: >15}\ndatablobs:    {: >15}\npackfiles:    {: >15}".format(tree_num, data_num, pack_num))
    print("---- Done ----")

if __name__=="__main__":

    test_simple_decrypt() # simple test

    # password = b"test"
    # masterkey = get_masterkey("repo/keys/e67c41...", password)

    # print(decrypt_packfile(masterkey, "repo/data/96/96ff07..."))

    # print(decrypt_config_index_snapshot(masterkey, "repo/snapshots/ae73930..."))
    # print(decrypt_config_index_snapshot(masterkey, "repo/config"))
    # print(decrypt_config_index_snapshot(masterkey, "repo/index/e6b2f8..."))

    # print(get_pack_content_lengths(masterkey, "repo/data/96/96ff07..."))
    # get_all_pack_content_lengths(masterkey, "repo/data")
