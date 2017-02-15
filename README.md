# restic repository pack file decryptor in Python

[restic](https://github.com/restic/restic) is a fast, efficient and secure backup program written in Go.

This script is neither fast, efficient nor secure.

This is a minimal implementation of decryption of individual restic repository pack files.

**This script does not restore your backups.**

The following features are implemented:

- Password hashing with scrypt
- Decryption of master key
- Decryption of the `IV || ciphertext || MAC` format using AES-256 CTR
- Parsing and decryption of the restic pack format
- Pack file content lengths based on type

The following features are NOT implemented:

- Everything else.

## Usage

```
>>> password = b"test"
>>> masterkey = get_masterkey("repo/keys/da2d948...", password)
>>> decrypt_packfile(masterkey, "repo/data/96/96f1f07...")
[
    {
        'type': 'data',
        'length': 175,
        'decrypted_content':
            b'SUPERIMPORTANTDATA 0101010101010101010101010101010101010...',
        'offset': 0,
        'id': b'3e2e046f6196f2046c47bf018475166de199bcc614c0154cd8b86fbc8dddffc9'
    },
    {
        'type': 'tree',
        'length': 358,
        'decrypted_content':
            b'{"nodes":[{"name":"header","type":"file","mode":420,"mtime":"2017-01-30T2..."}]}',
        'offset': 175,
        'id': b'9b86a829a4eb4fecd9801f667511967a53a09ad4a4a7bac6efcc4c9dd2a0b9bb'
    }
]
>>> get_all_pack_content_lengths(masterkey, "repo/data")
dir: repo/data h:0 t:0 d:0
dir: repo/data/15 h:106 t:331 d:92
dir: repo/data/1e h:212 t:662 d:198
header_length:            212
tree_length:              662
data_length:              198
```

Details on the restic repository format can be found in the [restic design document](https://restic.readthedocs.io/en/latest/Design/).

```
# restic version
restic 0.4.0 (v0.4.0-0-ga7c2f28-dirty)
compiled with go1.7.5 on linux/386
```
