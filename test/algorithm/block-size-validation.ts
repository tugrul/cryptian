
import {expect} from '@jest/globals';

import {default as cryptian, padding, BlockAlgorithmList, StreamAlgorithmList} from '../..';

const {algorithm, mode} = cryptian;

// The raw encrypt and decrypt entry points are a single block primitive. They
// used to accept anything: most ciphers returned only the first block and
// dropped the rest, while Twofish and Serpent returned a buffer of the input
// length whose trailing partial block was left as zeros. That second form was
// the dangerous one, because the length looked correct and a round trip
// silently replaced the tail of the plaintext with zero bytes.
describe('raw algorithm api takes exactly one block', () => {

    const blockAlgorithms = Object.values(BlockAlgorithmList);

    blockAlgorithms.forEach(name => {

        describe(name, () => {

            const create = () => {
                const instance = new algorithm[name]();
                instance.setKey(Buffer.alloc(32, 0x01));
                return instance;
            };

            it('accepts exactly one block', () => {

                const instance = create();
                const blockSize = instance.getBlockSize();

                expect(instance.encrypt(Buffer.alloc(blockSize, 0x41)).length).toBe(blockSize);
            });

            it('rejects a partial block', () => {

                const instance = create();
                const blockSize = instance.getBlockSize();

                expect(() => instance.encrypt(Buffer.alloc(blockSize - 1, 0x41))).toThrow(/block size/);
                expect(() => instance.decrypt(Buffer.alloc(blockSize - 1, 0x41))).toThrow(/block size/);
            });

            it('rejects a block and a half', () => {

                const instance = create();
                const blockSize = instance.getBlockSize();

                // This is the shape that used to come back with a zeroed tail.
                expect(() => instance.encrypt(Buffer.alloc(blockSize + 4, 0x41))).toThrow(/block size/);
            });

            it('rejects several whole blocks', () => {

                const instance = create();
                const blockSize = instance.getBlockSize();

                expect(() => instance.encrypt(Buffer.alloc(blockSize * 3, 0x41))).toThrow(/block size/);
            });

            it('rejects empty input', () => {

                expect(() => create().encrypt(Buffer.alloc(0))).toThrow(/block size/);
            });

            it('round trips one block', () => {

                const blockSize = create().getBlockSize();
                const plaintext = Buffer.alloc(blockSize, 0x41);

                expect(create().decrypt(create().encrypt(plaintext)).equals(plaintext)).toBe(true);
            });
        });
    });

    // Stream algorithms have no block, so nothing here applies to them.
    describe('stream algorithms are unaffected', () => {

        Object.values(StreamAlgorithmList).forEach(name => {

            it(name + ' accepts an arbitrary length', () => {

                const instance = new algorithm[name]();
                instance.setKey(Buffer.alloc(13, 0x01));

                expect(instance.encrypt(Buffer.alloc(37, 0x41)).length).toBe(37);
            });
        });
    });

    // The supported route for longer data, and the thing the error points at.
    describe('modes are the route for longer data', () => {

        it('ecb handles many blocks where the raw api will not', () => {

            const build = () => {
                const instance = new algorithm.Rijndael128();
                instance.setKey(Buffer.alloc(16, 0x01));
                return instance;
            };

            const plaintext = Buffer.alloc(16 * 5, 0x41);

            expect(() => build().encrypt(plaintext)).toThrow(/block size/);

            const cipher = new mode.ecb.Cipher(build(), Buffer.alloc(0));
            const decipher = new mode.ecb.Decipher(build(), Buffer.alloc(0));

            expect(decipher.transform(cipher.transform(plaintext)).equals(plaintext)).toBe(true);
        });

        it('a mode with padding handles data that is not block aligned', () => {

            const build = () => {
                const instance = new algorithm.Twofish();
                instance.setKey(Buffer.alloc(16, 0x01));
                return instance;
            };

            // 20 bytes against a 16 byte block: the case that used to come back
            // with four zero bytes on the end.
            const plaintext = Buffer.alloc(20, 0x41);

            const cipher = new mode.cbc.Cipher(build(), Buffer.alloc(16, 0x02));
            const decipher = new mode.cbc.Decipher(build(), Buffer.alloc(16, 0x02));

            const padder = new padding.Pkcs7(cipher.getBlockSize());

            const recovered = padder.unpad(decipher.transform(cipher.transform(padder.pad(plaintext))));

            expect(recovered.equals(plaintext)).toBe(true);
        });
    });
});
