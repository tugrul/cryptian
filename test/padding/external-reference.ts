
import {expect} from '@jest/globals';

import {createCipheriv} from 'crypto';

import {default as cryptian, padding} from '../..';
import Padding from '../../dist/padding';

const {algorithm, mode} = cryptian;

// The padding classes had unit tests but nothing outside this library to check
// them against. OpenSSL's automatic padding is PKCS#7, which gives the two
// counted schemes a real reference. The rest have no OpenSSL equivalent and are
// checked against their published definitions, written out here so the padder
// and the reference share no code.
describe('padding against outside references', () => {

    describe('pkcs7 matches openssl automatic padding', () => {

        const key = Buffer.alloc(16, 0x07);
        const iv = Buffer.alloc(16, 0x09);

        const lengths = Array.from({length: 65}, (unused, i) => i);

        it('produces the same ciphertext for every length up to four blocks', () => {

            lengths.forEach(length => {

                const plaintext = Buffer.alloc(length, 0x41);

                const openssl = createCipheriv('aes-128-cbc', key, iv);
                const expected = Buffer.concat([openssl.update(plaintext), openssl.final()]);

                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);

                const cipher = new mode.cbc.Cipher(rijndael, iv);
                const actual = cipher.transform(new padding.Pkcs7(16).pad(plaintext));

                expect(actual.equals(expected)).toBe(true);
            });
        });

        it('removes the padding openssl applied', () => {

            lengths.forEach(length => {

                const plaintext = Buffer.alloc(length, 0x42);

                const openssl = createCipheriv('aes-128-cbc', key, iv);
                const ciphertext = Buffer.concat([openssl.update(plaintext), openssl.final()]);

                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);

                const decipher = new mode.cbc.Decipher(rijndael, iv);
                const recovered = new padding.Pkcs7(16).unpad(decipher.transform(ciphertext));

                expect(recovered.equals(plaintext)).toBe(true);
            });
        });
    });

    describe('pkcs5 matches openssl at an eight byte block', () => {

        it('produces the same ciphertext through triple des', () => {

            const key = Buffer.alloc(24, 0x07);
            const iv = Buffer.alloc(8, 0x09);

            Array.from({length: 33}, (unused, i) => i).forEach(length => {

                const plaintext = Buffer.alloc(length, 0x41);

                const openssl = createCipheriv('des-ede3-cbc', key, iv);
                const expected = Buffer.concat([openssl.update(plaintext), openssl.final()]);

                const tripledes = new algorithm.Tripledes();
                tripledes.setKey(key);

                const cipher = new mode.cbc.Cipher(tripledes, iv);
                const actual = cipher.transform(new padding.Pkcs5(8).pad(plaintext));

                expect(actual.equals(expected)).toBe(true);
            });
        });
    });

    describe('the schemes openssl does not implement', () => {

        const blockSize = 16;

        // Written from the published descriptions rather than from the
        // implementation, so a shared misunderstanding cannot pass both.
        const references: Array<[string, new (blockSize: number) => Padding, (plaintext: Buffer) => Buffer]> = [
            [
                'ansi x9.23',
                padding.AnsiX923,
                plaintext => {
                    const size = blockSize - (plaintext.length % blockSize);
                    const padded = Buffer.concat([plaintext, Buffer.alloc(size)]);
                    padded[padded.length - 1] = size;
                    return padded;
                }
            ],
            [
                'iso 7816-4',
                padding.Iso7816,
                plaintext => {
                    const size = blockSize - (plaintext.length % blockSize);
                    const pad = Buffer.alloc(size);
                    pad[0] = 0x80;
                    return Buffer.concat([plaintext, pad]);
                }
            ],
            [
                'null',
                padding.Null,
                plaintext => Buffer.concat([plaintext, Buffer.alloc(blockSize - (plaintext.length % blockSize))])
            ],
            [
                'space',
                padding.Space,
                plaintext => Buffer.concat([plaintext, Buffer.alloc(blockSize - (plaintext.length % blockSize), 0x20)])
            ]
        ];

        references.forEach(([name, Padder, reference]) => {

            it(name + ' matches its definition and round trips', () => {

                for (let length = 0; length <= 40; length++) {

                    const plaintext = Buffer.alloc(length);

                    // Deliberately avoids ending in a zero or a space, which
                    // the filler schemes cannot recover by design.
                    for (let i = 0; i < length; i++) {
                        plaintext[i] = (i * 7 + 3) & 0xFF;
                    }

                    const padder = new Padder(blockSize);
                    const padded = padder.pad(plaintext);

                    expect(padded.equals(reference(plaintext))).toBe(true);
                    expect(padder.unpad(padded).equals(plaintext)).toBe(true);
                }
            });
        });
    });
});
