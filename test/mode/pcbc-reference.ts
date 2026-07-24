
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// libmcrypt has no pcbc module, so unlike every other mode here there is no
// mcrypt output to compare against. It is checked instead against a separate
// implementation of the published definition, written directly against the
// single block entry point, so the mode class and the reference share nothing
// but the cipher itself.
//
//   C[i] = E(P[i] xor P[i-1] xor C[i-1])
//
// with P[-1] xor C[-1] taken as the initialization vector.
describe('pcbc mode against an independent implementation', () => {

    const blockSize = 16;

    const reference = (key: Buffer, iv: Buffer, plaintext: Buffer) => {

        const cipher = new algorithm.Rijndael128();
        cipher.setKey(key);

        const output = Buffer.alloc(plaintext.length);
        const feedback = Buffer.from(iv);

        for (let offset = 0; offset < plaintext.length; offset += blockSize) {

            const block = plaintext.subarray(offset, offset + blockSize);
            const input = Buffer.alloc(blockSize);

            for (let i = 0; i < blockSize; i++) {
                input[i] = block[i] ^ feedback[i];
            }

            const encrypted = cipher.encrypt(input);
            encrypted.copy(output, offset);

            for (let i = 0; i < blockSize; i++) {
                feedback[i] = block[i] ^ encrypted[i];
            }
        }

        return output;
    };

    const cases = Array.from({length: 20}, (unused, t) => {

        const key = Buffer.alloc(16);
        const iv = Buffer.alloc(16);
        const plaintext = Buffer.alloc(blockSize * (1 + (t % 5)));

        for (let i = 0; i < key.length; i++) {
            key[i] = (t * 31 + i * 7) & 0xFF;
        }

        for (let i = 0; i < iv.length; i++) {
            iv[i] = (t * 17 + i * 5) & 0xFF;
        }

        for (let i = 0; i < plaintext.length; i++) {
            plaintext[i] = (t * 13 + i * 3) & 0xFF;
        }

        return {key, iv, plaintext};
    });

    cases.forEach(({key, iv, plaintext}, index) => {

        it('matches the reference for case ' + index, () => {

            const cipher = new algorithm.Rijndael128();
            cipher.setKey(key);

            expect(new mode.pcbc.Cipher(cipher, iv).transform(plaintext))
                .toEqual(reference(key, iv, plaintext));
        });

        it('round trips case ' + index, () => {

            const encryptKey = new algorithm.Rijndael128();
            encryptKey.setKey(key);

            const decryptKey = new algorithm.Rijndael128();
            decryptKey.setKey(key);

            const encrypted = new mode.pcbc.Cipher(encryptKey, iv).transform(plaintext);

            expect(new mode.pcbc.Decipher(decryptKey, iv).transform(encrypted))
                .toEqual(plaintext);
        });
    });
});
