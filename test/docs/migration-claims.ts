
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// docs/migrating-from-php-mcrypt.md makes concrete claims about block sizes,
// key handling and the blowfish compat flag. They are asserted here so the
// guide cannot drift away from the library without something failing.
describe('migration guide claims', () => {

    describe('the rijndael number is the block size, not the key size', () => {

        const blocks = [
            {name: 'Rijndael128', Algorithm: algorithm.Rijndael128, blockSize: 16},
            {name: 'Rijndael192', Algorithm: algorithm.Rijndael192, blockSize: 24},
            {name: 'Rijndael256', Algorithm: algorithm.Rijndael256, blockSize: 32}
        ];

        blocks.forEach(({name, Algorithm, blockSize}) => {

            it(name + ' has a ' + blockSize + ' byte block and accepts 16, 24 and 32 byte keys', () => {

                const instance = new Algorithm();

                expect(instance.getBlockSize()).toBe(blockSize);
                expect(instance.getKeySizes()).toEqual([16, 24, 32]);
            });

            it(name + ' requires an iv as wide as its block', () => {

                const instance = new Algorithm();
                instance.setKey(Buffer.alloc(32, 0x01));

                expect(() => {
                    new mode.cbc.Cipher(instance, Buffer.alloc(blockSize, 0x02));
                }).not.toThrow();

                // 16 bytes is correct only for the 128 bit block, so this is
                // the mistake someone makes when they assume AES widths.
                if (blockSize !== 16) {
                    expect(() => {
                        new mode.cbc.Cipher(instance, Buffer.alloc(16, 0x02));
                    }).toThrow(/Iv size/);
                }
            });
        });

        it('rijndael-256 is not aes-256, which uses a 16 byte block', () => {

            expect(new algorithm.Rijndael256().getBlockSize())
                .not.toBe(new algorithm.Rijndael128().getBlockSize());
        });
    });

    describe('short keys are zero padded the way mcrypt padded them', () => {

        it('a six byte key behaves as that key followed by zero bytes', () => {

            const short = Buffer.from('secret');
            const padded = Buffer.concat([short, Buffer.alloc(16 - short.length)]);

            const encryptWith = (key: Buffer) => {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                return new mode.ecb.Cipher(rijndael, Buffer.alloc(0))
                    .transform(Buffer.alloc(16, 0x41));
            };

            expect(encryptWith(short).equals(encryptWith(padded))).toBe(true);
        });
    });

    describe('blowfish compat is a byte order switch', () => {

        it('setEndianCompat changes the ciphertext', () => {

            const key = Buffer.alloc(16, 0x01);
            const iv = Buffer.alloc(8, 0x02);
            const plaintext = Buffer.alloc(8, 0x41);

            const encryptWith = (compat: boolean) => {
                const blowfish = new algorithm.Blowfish();
                blowfish.setKey(key);
                blowfish.setEndianCompat(compat);
                return new mode.cbc.Cipher(blowfish, iv).transform(plaintext);
            };

            expect(encryptWith(true).equals(encryptWith(false))).toBe(false);
        });
    });

    describe('safer64 and safer128 are one cipher selected by key length', () => {

        it('accepts both an 8 and a 16 byte key', () => {

            expect(new algorithm.Safer().getKeySizes()).toEqual([8, 16]);

            expect(() => {
                const safer = new algorithm.Safer();
                safer.setKey(Buffer.alloc(8, 0x01));
                safer.encrypt(Buffer.alloc(8, 0x41));
            }).not.toThrow();

            expect(() => {
                const safer = new algorithm.Safer();
                safer.setKey(Buffer.alloc(16, 0x01));
                safer.encrypt(Buffer.alloc(8, 0x41));
            }).not.toThrow();
        });
    });

    describe('stream ciphers take no mode wrapper', () => {

        it('arcfour round trips directly', () => {

            const plaintext = Buffer.from('stream mode');

            const encrypt = new algorithm.Arcfour();
            encrypt.setKey(Buffer.alloc(16, 0x01));

            const decrypt = new algorithm.Arcfour();
            decrypt.setKey(Buffer.alloc(16, 0x01));

            expect(decrypt.decrypt(encrypt.encrypt(plaintext)).equals(plaintext)).toBe(true);
        });
    });
});
