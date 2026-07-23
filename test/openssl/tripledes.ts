
import {expect} from '@jest/globals';

import {default as cryptian,
    padding, createEncryptStream, createDecryptStream, ModeList} from '../..';

const {algorithm, mode} = cryptian;

import { randomBytes, createDecipheriv, createCipheriv, getCiphers } from 'crypto';

import streamBuffers from 'stream-buffers';

// Tripledes maps onto the OpenSSL des-ede3 family. Single DES is not in the
// OpenSSL 3 default provider, so des.ts skips on modern Node and this file is
// what actually exercises interop for an eight byte block. Note that cryptian follows the mcrypt naming:
// cfb is the 8 bit variant and ncfb is the full block one, while ofb is the
// 8 bit variant and nofb is the full block one. OpenSSL exposes no 8 bit OFB,
// so cryptian ofb has no counterpart and is covered by the mcrypt vectors in
// test/transform instead.
(typeof algorithm.Tripledes === 'function' ? describe : describe.skip) ('tripledes with openssl des-ede3 compat', () => {

    const modes: Array<{name: ModeList, openssl: string, skipIv?: boolean}> = [
        { name: ModeList.Cbc, openssl: 'des-ede3-cbc' },
        { name: ModeList.Ecb, openssl: 'des-ede3-ecb', skipIv: true },
        { name: ModeList.Cfb, openssl: 'des-ede3-cfb8' },
        { name: ModeList.Ncfb, openssl: 'des-ede3-cfb' },
        { name: ModeList.Nofb, openssl: 'des-ede3-ofb' }
    ];

    // list of available ciphers
    const ciphers = getCiphers();

    modes.forEach(({name, openssl, skipIv}) => {

        const targetMode = mode[name];

        // The guard has to test the OpenSSL name. Testing the cryptian name
        // never matches anything getCiphers returns, which silently skipped
        // every case in this file.
        (typeof targetMode === 'object' && ciphers.includes(openssl) ? describe : describe.skip) (name + ' mode pkcs7 padding', () => {

            it('encrypt cryptian to decrypt openssl', async () => {

                const iv  = skipIv ? Buffer.alloc(0) : randomBytes(8);
                const key = randomBytes(24);
                const plaintext = randomBytes(50);

                const tripledes = new algorithm.Tripledes();
                tripledes.setKey(key);
                const cipher = new targetMode.Cipher(tripledes, iv);

                const encryptTransform = createEncryptStream(cipher, padding.Pkcs7);
                const decryptTransform = encryptTransform.pipe(createDecipheriv(openssl, key, skipIv ? null : iv));
                const buffer           = decryptTransform.pipe(new streamBuffers.WritableStreamBuffer());

                // The assertions used to sit in a finish handler while the test
                // itself was synchronous, so the test completed before they ran
                // and a mismatch could not fail anything.
                const finished = new Promise<void>((resolve, reject) => {
                    buffer.on('finish', () => resolve());
                    buffer.on('error', reject);
                    encryptTransform.on('error', reject);
                    decryptTransform.on('error', reject);
                });

                encryptTransform.write(plaintext.subarray(0, 22));
                encryptTransform.write(plaintext.subarray(22, 39));
                encryptTransform.end(plaintext.subarray(39));

                await finished;

                const contents = buffer.getContents();

                expect(contents).toBeTruthy();
                expect((contents as Buffer).toString('hex')).toBe(plaintext.toString('hex'));
            });


            it('encrypt openssl to decrypt cryptian', async () => {

                const iv  = skipIv ? Buffer.alloc(0) : randomBytes(8);
                const key = randomBytes(24);
                const plaintext = randomBytes(50);

                const tripledes = new algorithm.Tripledes();
                tripledes.setKey(key);
                const decipher = new targetMode.Decipher(tripledes, iv);

                const encryptTransform = createCipheriv(openssl, key, skipIv ? null : iv);
                const decryptTransform = encryptTransform.pipe(createDecryptStream(decipher, padding.Pkcs7));
                const buffer           = decryptTransform.pipe(new streamBuffers.WritableStreamBuffer());

                const finished = new Promise<void>((resolve, reject) => {
                    buffer.on('finish', () => resolve());
                    buffer.on('error', reject);
                    encryptTransform.on('error', reject);
                    decryptTransform.on('error', reject);
                });

                encryptTransform.write(plaintext.subarray(0, 22));
                encryptTransform.write(plaintext.subarray(22, 39));
                encryptTransform.end(plaintext.subarray(39));

                await finished;

                const contents = buffer.getContents();

                expect(contents).toBeTruthy();
                expect((contents as Buffer).toString('hex')).toBe(plaintext.toString('hex'));
            });

        });

    });

});
