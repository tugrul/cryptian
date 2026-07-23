# cryptian [![Build & Test](https://github.com/tugrul/cryptian/actions/workflows/build-test.yml/badge.svg)](https://github.com/tugrul/cryptian/actions/workflows/build-test.yml) [![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Ftugrul%2Fcryptian.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Ftugrul%2Fcryptian?ref=badge_shield)

MCrypt compatible crypto wrapper for Node.js

Provides the ciphers, block cipher modes and paddings that libmcrypt had,
including the ones OpenSSL never exposed, so data written by PHP `mcrypt` can
still be read after its removal in PHP 7.2.

**Migrating from PHP?** See [docs/migrating-from-php-mcrypt.md](docs/migrating-from-php-mcrypt.md).
It maps every mcrypt constant onto this library and covers the three things
that most often go wrong: `MCRYPT_RIJNDAEL_256` is a 256 bit *block* and is not
AES-256, `mcrypt_encrypt()` padded with null bytes rather than PKCS#7, and the
mcrypt mode names do not line up with the OpenSSL ones (`cfb` is 8 bit, `ncfb`
is the full block variant).

## Intended use

These algorithms exist to read existing data. Most of them are obsolete and
several are broken. None of the modes here authenticate, so ciphertext can be
altered without detection. For new work use an AEAD construction such as
AES-GCM from node's built-in `crypto`, and treat this library as a migration
tool: decrypt once, re-encrypt with something modern.

## Install

### Using NPM

```
npm install --save cryptian
```

### Using Yarn

```
yarn add cryptian
```

## Basic Usage With Transform Stream Support

Check out the *test* folder to find out the different ways to use it.

### Block Algorithm Encryption

```javascript
const fs = require('fs');
const {default: {algorithm, mode}, padding, createEncryptStream} = require('cryptian');

const key = Buffer.from('0a0c0e1012141618', 'hex');
const iv = Buffer.from('ca40f5af0b1aeea2', 'hex');

const des = new algorithm.Des();
des.setKey(key);

const cipher = new mode.cbc.Cipher(des, iv);

fs.createReadStream('test.png')
    .pipe(createEncryptStream(cipher, padding.Pkcs5))
    .pipe(fs.createWriteStream('test.png.encrypted'));
```

### Block Algorithm Decryption

```javascript
const fs = require('fs');
const {default: {algorithm, mode}, padding, createDecryptStream} = require('cryptian');

const key = Buffer.from('0a0c0e1012141618', 'hex');
const iv = Buffer.from('ca40f5af0b1aeea2', 'hex');

const des = new algorithm.Des();
des.setKey(key);

const cipher = new mode.cbc.Decipher(des, iv);

fs.createReadStream('test.png.encrypted')
    .pipe(createDecryptStream(cipher, padding.Pkcs5))
    .pipe(fs.createWriteStream('test-decrypted.png'));
```


## Available Crypto Algorithms

All the following crypto algorithms ported from libmcrypt

### Block Cipher

* Blowfish
* CAST-128
* CAST-256
* DES
* GOST
* LOKI97
* RC2
* Rijndael-128 (AES-128)
* Rijndael-192
* Rijndael-256
* SAFER
* SAFER+
* 3-Way
* 3DES
* XTEA

#### Basic Usage

```javascript
const assert = require('assert');
const {default: {algorithm}} = require('cryptian');
const des = new algorithm.Des();

des.setKey(Buffer.from('0a0c0e1012141618', 'hex'));

const ciphertext = Buffer.from('a1502d70ba1320c8', 'hex');
const plaintext  = Buffer.from('0001020304050607', 'hex');

assert(ciphertext.equals(des.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');
assert(plaintext.equals(des.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');
```

### Stream Cipher

* RC4 (Arcfour)
* Enigma
* WAKE

#### Basic Usage

```javascript
const assert = require('assert');
const {default: {algorithm}} = require('cryptian');

const enigma = new algorithm.Enigma();

enigma.setKey(Buffer.from('enadyotr', 'ascii'));

const ciphertext = Buffer.from('f3edda7da20f8975884600f014d32c7a08e59d7b', 'hex');
const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f10111213', 'hex');

assert(ciphertext.equals(enigma.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');
assert(plaintext.equals(enigma.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');
```

## Available Block Cipher Mode Algorithms

All the following block cipher mode algorithms ported from libmcrypt

| cryptian | width | PHP mcrypt | OpenSSL |
| --- | --- | --- | --- |
| `cbc` | block | `MCRYPT_MODE_CBC` | `aes-128-cbc` |
| `pcbc` | block | none | none |
| `cfb` | 8 bit | `MCRYPT_MODE_CFB` | `aes-128-cfb8` |
| `ncfb` | block | `'ncfb'` | `aes-128-cfb` |
| `ctr` | block | `'ctr'` | `aes-128-ctr` |
| `ecb` | block | `MCRYPT_MODE_ECB` | `aes-128-ecb` |
| `ofb` | 8 bit | `MCRYPT_MODE_OFB` | none |
| `nofb` | block | `MCRYPT_MODE_NOFB` | `aes-128-ofb` |

Note that OpenSSL's `aes-128-cfb` is the full block variant and corresponds to
`ncfb`, not `cfb`, and that `aes-128-ofb` corresponds to `nofb`, not `ofb`.
These pairings are verified in `test/openssl`.

### Basic Usage

```javascript
const assert = require('assert');
const {default: {algorithm, mode}} = require('cryptian');

const plaintext  = Buffer.from('88cc3d134aee5660f7623cf475fe9df20f773180bd70b0ef2aae00910ba087a1', 'hex');
const ciphertext = Buffer.from('ace98b99e6803c445b8bb76d937ea1b654fc86ed2e0e11597e52867c25ae96f8', 'hex');

const iv = Buffer.from('2425b68aac6e6a24', 'hex');

// don't use Dummy algorithm in real production environment 
// because this is not an encryption algorithm
const dummy = new algorithm.Dummy(); 

const cipher = new mode.cbc.Cipher(dummy, iv);
assert(ciphertext.equals(cipher.transform(plaintext)), 'transformed plaintext should be equal to ciphertext');

const decipher = new mode.cbc.Decipher(dummy, iv);
assert(plaintext.equals(decipher.transform(ciphertext)), 'transformed ciphertext should be equal to plaintext');
```

## Available Block Cipher Padding Algorithms

* ANSI-x923
* ISO-10126
* ISO-7816
* NULL bytes
* PKCS5
* PKCS7
* Space character bytes

### Basic Usage

```javascript
const assert = require('assert');
const {padding} = require('cryptian');

const padder = new padding.Pkcs5(8);
const padded = Buffer.from('0575ba559d030303', 'hex');
const unpadded = Buffer.from('0575ba559d', 'hex');

assert(padded.equals(padder.pad(unpadded)));
assert(unpadded.equals(padder.unpad(padded)));
```

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Ftugrul%2Fcryptian.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Ftugrul%2Fcryptian?ref=badge_large)
