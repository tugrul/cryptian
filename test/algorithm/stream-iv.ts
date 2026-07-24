
import {expect} from '@jest/globals';

import {default as cryptian, StreamAlgorithmList} from '../..';

const {algorithm} = cryptian;

// setIv mirrors setKey: rebuild only when the vector actually changed. The
// negation was missing from that test, which inverted it. A different vector of
// the same length was discarded without being stored, so the cipher carried on
// with the previous one, and setting the same vector twice rebuilt for nothing.
//
// Arcfour had a second, worse problem in the same area. Its schedule indexed
// _iv[i + 1 % _iv.size()], and since the modulus binds tighter than the
// addition that is _iv[i + 1], which runs to 256 on a vector of far fewer
// bytes. It read past the end on most iterations, so the output depended on
// whatever followed the allocation and varied between identical runs.
describe('stream algorithm initialization vectors', () => {

    const withIv = Object.values(StreamAlgorithmList)
        .filter(name => new algorithm[name]().getIvSize() > 0);

    const plaintext = Buffer.alloc(16, 0x41);

    withIv.forEach(name => {

        describe(name, () => {

            const probe = new algorithm[name]();
            const keySize = probe.getKeySizes()[0];
            const ivSize = probe.getIvSize();

            const key = Buffer.alloc(keySize, 0x01);
            const first = Buffer.alloc(ivSize, 0xAA);
            const second = Buffer.alloc(ivSize, 0xBB);

            const encryptWith = (...ivs: Array<Buffer>) => {
                const instance = new algorithm[name]();
                instance.setKey(key);
                ivs.forEach(iv => instance.setIv(iv));
                return instance.encrypt(plaintext).toString('hex');
            };

            it('produces the same output for the same inputs every time', () => {

                const results = new Set(
                    Array.from({length: 8}, () => encryptWith(first))
                );

                // More than one distinct result means the schedule is reading
                // something that is not part of the key or the vector.
                expect(results.size).toBe(1);
            });

            it('produces different output for a different vector', () => {

                expect(encryptWith(first)).not.toBe(encryptWith(second));
            });

            it('honours a vector set after another of the same length', () => {

                expect(encryptWith(second, first)).toBe(encryptWith(first));
            });

            it('is unaffected by setting the same vector twice', () => {

                expect(encryptWith(first, first)).toBe(encryptWith(first));
            });

            it('round trips with the vector applied', () => {

                const encryptor = new algorithm[name]();
                encryptor.setKey(key);
                encryptor.setIv(first);

                const decryptor = new algorithm[name]();
                decryptor.setKey(key);
                decryptor.setIv(first);

                expect(decryptor.decrypt(encryptor.encrypt(plaintext)).equals(plaintext)).toBe(true);
            });

            it('accepts a vector shorter than the reported size', () => {

                // Short vectors are indexed with a wrap, so they must not read
                // beyond what was supplied.
                const results = new Set(
                    Array.from({length: 8}, () => encryptWith(Buffer.alloc(1, 0xCC)))
                );

                expect(results.size).toBe(1);
            });
        });
    });
});
