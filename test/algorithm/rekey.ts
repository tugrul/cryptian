
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// setKey skips rebuilding the key schedule when the key has not changed. The
// comparison relies on the size check short circuiting before std::equal runs,
// because that overload takes no end iterator for the second range and would
// otherwise read past the end of the stored key when the new one is longer.
// These cases exercise growing, shrinking and repeating a key.
describe('rekeying an algorithm instance', () => {

    const encryptWith = (rijndael: InstanceType<typeof algorithm.Rijndael128>) =>
        new mode.ecb.Cipher(rijndael, Buffer.alloc(0))
            .transform(Buffer.alloc(16, 0x41))
            .toString('hex');

    const freshResult = (length: number) => {
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(Buffer.alloc(length, 0x01));
        return encryptWith(rijndael);
    };

    it('produces the same result as a fresh instance after every change', () => {

        const reused = new algorithm.Rijndael128();

        // Grow, shrink and repeat. Growing is the case that would read past the
        // end of the stored key if the size check did not come first.
        [16, 32, 16, 24, 24, 16, 32].forEach(length => {

            reused.setKey(Buffer.alloc(length, 0x01));

            expect(encryptWith(reused)).toBe(freshResult(length));
        });
    });

    it('gives different output for different key lengths', () => {

        const results = [16, 24, 32].map(freshResult);

        expect(new Set(results).size).toBe(results.length);
    });

    it('gives different output for different keys of the same length', () => {

        const rijndael = new algorithm.Rijndael128();

        rijndael.setKey(Buffer.alloc(16, 0x01));
        const first = encryptWith(rijndael);

        rijndael.setKey(Buffer.alloc(16, 0x02));
        const second = encryptWith(rijndael);

        expect(first).not.toBe(second);

        // Setting the original key back must restore the original schedule.
        rijndael.setKey(Buffer.alloc(16, 0x01));
        expect(encryptWith(rijndael)).toBe(first);
    });

    it('handles a key that shares a prefix with the previous one', () => {

        const rijndael = new algorithm.Rijndael128();

        rijndael.setKey(Buffer.concat([Buffer.alloc(16, 0x01), Buffer.alloc(16, 0x02)]));
        const long = encryptWith(rijndael);

        // A prefix of the previous key. The size check is the only thing that
        // distinguishes these two.
        rijndael.setKey(Buffer.alloc(16, 0x01));
        const short = encryptWith(rijndael);

        expect(long).not.toBe(short);
        expect(short).toBe(freshResult(16));
    });
});
