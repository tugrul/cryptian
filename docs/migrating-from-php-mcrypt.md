# Migrating from PHP mcrypt

`mcrypt` was deprecated in PHP 7.1 and removed in 7.2. Data encrypted with it
did not disappear with it, and OpenSSL will not read most of it, because mcrypt
supported block sizes and modes that OpenSSL never exposed.

This guide maps mcrypt calls onto cryptian. Every table here was verified
against the running library rather than transcribed from documentation. The
mode mappings in particular are checked by `test/openssl`.

## Read this part first

Three mcrypt behaviours were implicit. Missing any one of them produces output
that looks plausible and is wrong.

### MCRYPT_RIJNDAEL_256 is not AES-256

This is the single most common migration mistake. In mcrypt, the number is the
**block size**, not the key size.

| mcrypt constant | block size | key sizes | is it AES? |
| --- | --- | --- | --- |
| `MCRYPT_RIJNDAEL_128` | 128 bit | 128 / 192 / 256 bit | yes |
| `MCRYPT_RIJNDAEL_192` | 192 bit | 128 / 192 / 256 bit | no |
| `MCRYPT_RIJNDAEL_256` | 256 bit | 128 / 192 / 256 bit | no |

AES fixed Rijndael's block size at 128 bit. `MCRYPT_RIJNDAEL_256` is Rijndael
with a 256 bit block, which AES never standardised, so no OpenSSL build
implements it and `aes-256-cbc` will not decrypt it. AES-256 is
`MCRYPT_RIJNDAEL_128` with a 32 byte key.

If your PHP used `MCRYPT_RIJNDAEL_256`, cryptian is one of the few ways left to
read that data.

### mcrypt_encrypt padded with null bytes

`mcrypt_encrypt()` silently zero-padded the plaintext up to the block size. It
is not PKCS#7. Use `padding.Null` to reproduce it.

Null padding is ambiguous: it cannot represent plaintext that legitimately ends
in a zero byte, and unpadding cannot tell real trailing zeros from padding.
That ambiguity is inherited from mcrypt. For new data use `padding.Pkcs7`.

### mcrypt zero-padded short keys

If the key was shorter than the algorithm wanted, mcrypt padded it with zero
bytes instead of failing. cryptian does the same, so a short key produces the
same result it did in PHP:

```javascript
const short  = Buffer.from('secret');                                  // 6 bytes
const padded = Buffer.concat([short, Buffer.alloc(10)]);               // 16 bytes
// both produce identical ciphertext
```

Do not rely on this for new code. Derive a full length key instead.

## Cipher names

| mcrypt constant | cryptian | block | key sizes (bytes) |
| --- | --- | --- | --- |
| `MCRYPT_RIJNDAEL_128` | `algorithm.Rijndael128` | 16 | 16 / 24 / 32 |
| `MCRYPT_RIJNDAEL_192` | `algorithm.Rijndael192` | 24 | 16 / 24 / 32 |
| `MCRYPT_RIJNDAEL_256` | `algorithm.Rijndael256` | 32 | 16 / 24 / 32 |
| `MCRYPT_BLOWFISH` | `algorithm.Blowfish` | 8 | up to 56 |
| `MCRYPT_BLOWFISH_COMPAT` | `algorithm.Blowfish` + `setEndianCompat(true)` | 8 | up to 56 |
| `MCRYPT_CAST_128` | `algorithm.Cast128` | 8 | 16 |
| `MCRYPT_CAST_256` | `algorithm.Cast256` | 16 | 16 / 24 / 32 |
| `MCRYPT_DES` | `algorithm.Des` | 8 | 8 |
| `MCRYPT_3DES`, `MCRYPT_TRIPLEDES` | `algorithm.Tripledes` | 8 | 24 |
| `MCRYPT_GOST` | `algorithm.Gost` | 8 | 32 |
| `MCRYPT_LOKI97` | `algorithm.Loki97` | 16 | 16 / 24 / 32 |
| `MCRYPT_RC2` | `algorithm.Rc2` | 8 | up to 128 |
| `MCRYPT_SAFER64` | `algorithm.Safer` with an 8 byte key | 8 | 8 |
| `MCRYPT_SAFER128` | `algorithm.Safer` with a 16 byte key | 8 | 16 |
| `MCRYPT_SAFERPLUS` | `algorithm.Saferplus` | 16 | 16 / 24 / 32 |
| `MCRYPT_THREEWAY` | `algorithm.Threeway` | 12 | 12 |
| `MCRYPT_XTEA` | `algorithm.Xtea` | 8 | 16 |
| `MCRYPT_ARCFOUR` | `algorithm.Arcfour` | stream | up to 256 |
| `MCRYPT_CRYPT` | `algorithm.Enigma` | stream | 13 |
| `MCRYPT_WAKE` | `algorithm.Wake` | stream | 32 |

`SAFER64` and `SAFER128` are the same cipher; the key length selects the
variant, so there is one `Safer` class.

`MCRYPT_BLOWFISH_COMPAT` is ordinary Blowfish with a different byte order.
Calling `setEndianCompat(true)` switches to it. Getting this wrong yields
ciphertext that is the right length and completely wrong.

### Not implemented

`MCRYPT_TWOFISH`, `MCRYPT_SERPENT`, `MCRYPT_PANAMA`, `MCRYPT_IDEA`,
`MCRYPT_RC6` and the `MCRYPT_SAFER_SK*` variants are not available.

## Mode names

The mcrypt naming is not obvious and does not match OpenSSL. In mcrypt an `n`
prefix means the full block width, and the unprefixed name means 8 bit.

| PHP mode | cryptian | what it is | OpenSSL name |
| --- | --- | --- | --- |
| `MCRYPT_MODE_ECB`, `'ecb'` | `mode.ecb` | electronic codebook | `aes-128-ecb` |
| `MCRYPT_MODE_CBC`, `'cbc'` | `mode.cbc` | cipher block chaining | `aes-128-cbc` |
| `MCRYPT_MODE_CFB`, `'cfb'` | `mode.cfb` | **8 bit** cipher feedback | `aes-128-cfb8` |
| `'ncfb'` | `mode.ncfb` | full block cipher feedback | `aes-128-cfb` |
| `MCRYPT_MODE_OFB`, `'ofb'` | `mode.ofb` | **8 bit** output feedback | none |
| `MCRYPT_MODE_NOFB`, `'nofb'` | `mode.nofb` | full block output feedback | `aes-128-ofb` |
| `'ctr'` | `mode.ctr` | counter | `aes-128-ctr` |
| `MCRYPT_MODE_STREAM`, `'stream'` | use the algorithm directly | no mode wrapper | n/a |

Two traps here:

- OpenSSL's `aes-128-cfb` is the **full block** variant, which is cryptian's
  `ncfb`, not `cfb`. PHP's `MCRYPT_MODE_CFB` is the 8 bit one.
- OpenSSL's `aes-128-ofb` is cryptian's **`nofb`**. There is no OpenSSL
  equivalent for cryptian's 8 bit `ofb`.

`pcbc` exists in cryptian but has no mcrypt or OpenSSL counterpart.

### When you do not need cryptian

If your data used `MCRYPT_RIJNDAEL_128` in `cbc`, `ecb`, `ncfb`, `nofb` or
`ctr`, node's built-in `crypto` can read it directly with the OpenSSL name
above, provided you handle the null padding yourself. cryptian is required for
the 192 and 256 bit block sizes, the 8 bit `cfb` and `ofb` modes, and the
ciphers OpenSSL dropped.

## Worked examples

### CBC with null padding

```php
$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $plaintext, MCRYPT_MODE_CBC, $iv);
```

```javascript
const {default: {algorithm, mode}, padding} = require('cryptian');

const rijndael = new algorithm.Rijndael128();
rijndael.setKey(key);

const cipher = new mode.cbc.Cipher(rijndael, iv);
const padder = new padding.Null(cipher.getBlockSize());

const ciphertext = cipher.transform(padder.pad(plaintext));
```

### Rijndael-256, which OpenSSL cannot read

```php
$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $plaintext, MCRYPT_MODE_CBC, $iv);
```

```javascript
const rijndael = new algorithm.Rijndael256();
rijndael.setKey(key);

// the block is 32 bytes here, so the iv must be 32 bytes too
const cipher = new mode.cbc.Cipher(rijndael, iv);
const padder = new padding.Null(cipher.getBlockSize());

const ciphertext = cipher.transform(padder.pad(plaintext));
```

The IV width follows the block, not the key. A 32 byte block needs a 32 byte
IV. Passing a 16 byte IV now throws rather than corrupting memory.

### Blowfish compat

```php
$ciphertext = mcrypt_encrypt(MCRYPT_BLOWFISH_COMPAT, $key, $plaintext, MCRYPT_MODE_CBC, $iv);
```

```javascript
const blowfish = new algorithm.Blowfish();
blowfish.setKey(key);
blowfish.setEndianCompat(true);   // this is what COMPAT means

const cipher = new mode.cbc.Cipher(blowfish, iv);
```

### Stream ciphers

`MCRYPT_MODE_STREAM` has no mode object. Use the algorithm directly, and do not
pad:

```php
$ciphertext = mcrypt_encrypt(MCRYPT_ARCFOUR, $key, $plaintext, MCRYPT_MODE_STREAM);
```

```javascript
const arcfour = new algorithm.Arcfour();
arcfour.setKey(key);

const ciphertext = arcfour.encrypt(plaintext);
```

### Decrypting a large file

For anything that does not fit comfortably in memory, use the stream helpers.
They handle block alignment and remove padding on the final chunk:

```javascript
const fs = require('fs');
const {default: {algorithm, mode}, padding, createDecryptStream} = require('cryptian');

const rijndael = new algorithm.Rijndael256();
rijndael.setKey(key);

fs.createReadStream('legacy.enc')
    .pipe(createDecryptStream(new mode.cbc.Decipher(rijndael, iv), padding.Null))
    .pipe(fs.createWriteStream('legacy.out'));
```

## Checklist

1. Is the constant `MCRYPT_RIJNDAEL_192` or `_256`? The number is the block
   size. It is not AES and the IV must match that width.
2. Did the data come from `mcrypt_encrypt()`? Use `padding.Null`.
3. Is the mode `cfb` or `ofb`? Those are the 8 bit variants. The full block
   ones are `ncfb` and `nofb`.
4. Is the constant `MCRYPT_BLOWFISH_COMPAT`? Call `setEndianCompat(true)`.
5. Was the key shorter than the cipher wanted? It was zero-padded, and still is.

## Security notes

These algorithms are here to read existing data. Most should not be chosen for
anything new.

- DES, single DES in particular, and RC2, RC4, Enigma and WAKE are broken or
  far too weak for current use.
- ECB reveals structure in the plaintext because identical blocks encrypt
  identically. Avoid it outside compatibility work.
- None of these modes authenticate. Ciphertext can be altered undetected. If
  you need integrity, use an AEAD construction such as AES-GCM from node's
  built-in `crypto`.
- The padding routines are not constant time. Do not use unpad failures to gate
  authentication decisions, or you may build a padding oracle.

The safe pattern for a migration is to decrypt with cryptian once and re-encrypt
with an authenticated modern cipher, rather than keeping the legacy scheme
alive.
