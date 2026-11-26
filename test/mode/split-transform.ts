
import {expect} from '@jest/globals';

import {createCipheriv, getCiphers} from 'crypto';

import {default as cryptian, ModeList, BlockAlgorithmList} from '../..';
import type {ModeCipherDecipher} from '../..';

const {algorithm, mode} = cryptian;

// A mode keeps its position between calls, so a message can be handed to
// transform() in any number of pieces. The modes that need no padding take
// pieces of any length, and the result has to be the same as for one call
// wherever the message is cut.
//
// The per-mode tests cut messages too, but with the Dummy algorithm, whose
// encrypt() returns its input. A mode that XORs with its register where it
// should XOR with the keystream produces the right bytes there, which is how
// such a fault in ncfb went unnoticed. These tests use real ciphers, messages
// long enough for a damaged register to show up in the next block, and every
// place a message can be cut.
describe('transform in pieces', () => {

    const modes: Array<{name: ModeList, openssl?: string}> = [
        { name: ModeList.Cfb, openssl: 'aes-128-cfb8' },
        { name: ModeList.Ofb },                             // OpenSSL has no 8 bit OFB
        { name: ModeList.Ncfb, openssl: 'aes-128-cfb' },
        { name: ModeList.Nofb, openssl: 'aes-128-ofb' },
        { name: ModeList.Ctr, openssl: 'aes-128-ctr' }
    ];

    const algorithms: Array<{name: BlockAlgorithmList, keySize: number, blockSize: number}> = [
        { name: BlockAlgorithmList.Des, keySize: 8, blockSize: 8 },
        { name: BlockAlgorithmList.Rijndael128, keySize: 16, blockSize: 16 },
        { name: BlockAlgorithmList.Rijndael256, keySize: 32, blockSize: 32 }
    ];

    const bytes = (length: number, step: number, first: number) =>
        Buffer.from(Array.from({length}, (_, i) => (first + i * step) & 0xff));

    // Hands data to transform() in pieces that end at the given offsets.
    const inPieces = (target: InstanceType<ModeCipherDecipher['Cipher']>, data: Buffer, cuts: number[]) => {

        const parts: Buffer[] = [];
        let from = 0;

        for (const to of [...cuts, data.length]) {
            parts.push(target.transform(data.subarray(from, to)));
            from = to;
        }

        return Buffer.concat(parts);
    };

    // Every way to cut a message into two or three pieces, and into four
    // pieces at the offsets where a mode changes what it does: just inside a
    // block, on a block boundary and just across one.
    const everyCut = (length: number, blockSize: number) => {

        const cuts: number[][] = [];

        for (let a = 1; a < length; a++) {
            cuts.push([a]);

            for (let b = a + 1; b < length; b++) {
                cuts.push([a, b]);
            }
        }

        const edges = [1, 5, blockSize - 1, blockSize, blockSize + 1, blockSize + 5,
            2 * blockSize - 1, 2 * blockSize, 2 * blockSize + 3, 3 * blockSize, 3 * blockSize + 1];

        for (let a = 0; a < edges.length; a++) {
            for (let b = a + 1; b < edges.length; b++) {
                for (let c = b + 1; c < edges.length; c++) {
                    cuts.push([edges[a], edges[b], edges[c]]);
                }
            }
        }

        return cuts;
    };

    modes.forEach(({name: modeName, openssl}) => {

        const targetMode = mode[modeName];

        algorithms.forEach(({name: algorithmName, keySize, blockSize}) => {

            const available = typeof targetMode === 'object' && typeof algorithm[algorithmName] === 'function';

            (available ? describe : describe.skip) (modeName + ' with ' + algorithmName, () => {

                // three blocks and a part of a fourth
                const plaintext = bytes(3 * blockSize + 5, 29, 0x3b);
                const key = bytes(keySize, 11, 0x85);
                const iv = bytes(blockSize, 17, 0x09);

                const cuts = everyCut(plaintext.length, blockSize);

                let cipher: InstanceType<typeof algorithm[typeof algorithmName]>;
                let ciphertext: Buffer;

                beforeAll(() => {
                    cipher = new algorithm[algorithmName]();
                    cipher.setKey(key);

                    ciphertext = new targetMode.Cipher(cipher, iv).transform(plaintext);
                });

                it('one call decrypts what one call encrypted', () => {
                    expect(ciphertext.length).toBe(plaintext.length);
                    expect(ciphertext.equals(plaintext)).toBe(false);
                    expect(new targetMode.Decipher(cipher, iv).transform(ciphertext).toString('hex'))
                        .toBe(plaintext.toString('hex'));
                });

                it('encrypts the same in pieces as in one call', () => {

                    const wrong = cuts.filter(cut =>
                        !inPieces(new targetMode.Cipher(cipher, iv), plaintext, cut).equals(ciphertext));

                    // an empty list, or the first cuts that went wrong
                    expect(wrong.slice(0, 5)).toEqual([]);
                });

                it('decrypts the same in pieces as in one call', () => {

                    const wrong = cuts.filter(cut =>
                        !inPieces(new targetMode.Decipher(cipher, iv), ciphertext, cut).equals(plaintext));

                    expect(wrong.slice(0, 5)).toEqual([]);
                });

                // Rijndael with a 128 bit block is AES. Where OpenSSL has the
                // mode, this ties the one-call result, and with it every
                // result above, to an independent implementation.
                if (algorithmName === BlockAlgorithmList.Rijndael128 && openssl !== undefined) {

                    (getCiphers().includes(openssl) ? it : it.skip) ('one call matches openssl ' + openssl, () => {

                        const reference = createCipheriv(openssl, key, iv);
                        const expected = Buffer.concat([reference.update(plaintext), reference.final()]);

                        expect(ciphertext.toString('hex')).toBe(expected.toString('hex'));
                    });
                }
            });
        });
    });
});
