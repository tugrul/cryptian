
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// A mode refers to its algorithm rather than copying it. That was implicit
// until the mode started holding a handle to keep it alive, and it has
// consequences worth stating: several modes can share one algorithm, and
// changing the key on that algorithm is seen by every mode using it.
describe('the relationship between a mode and its algorithm', () => {

    const iv = Buffer.alloc(16, 0x09);
    const plaintext = Buffer.alloc(16, 0x41);

    const keyed = (fill: number) => {
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(Buffer.alloc(16, fill));
        return rijndael;
    };

    it('lets several modes share one algorithm', () => {

        const shared = keyed(0x07);

        const throughShared = new mode.cbc.Cipher(shared, iv).transform(plaintext);
        const throughOwn = new mode.cbc.Cipher(keyed(0x07), iv).transform(plaintext);

        expect(throughShared.equals(throughOwn)).toBe(true);

        // The same instance still drives a second mode of a different kind.
        expect(new mode.ecb.Cipher(shared, Buffer.alloc(0)).transform(plaintext).length).toBe(16);
    });

    it('follows the algorithm when its key changes', () => {

        const rijndael = keyed(0x01);
        const cipher = new mode.ecb.Cipher(rijndael, Buffer.alloc(0));

        const before = cipher.transform(plaintext);

        rijndael.setKey(Buffer.alloc(16, 0x02));

        const after = cipher.transform(plaintext);

        // The mode holds the algorithm, not a copy of its key schedule, so the
        // change is visible. Rekeying an algorithm that a mode is using is
        // therefore something to do deliberately or not at all.
        expect(before.equals(after)).toBe(false);
        expect(after.equals(new mode.ecb.Cipher(keyed(0x02), Buffer.alloc(0)).transform(plaintext))).toBe(true);
    });

    it('rejects anything that is not a block algorithm', () => {

        // A stream algorithm, another mode and a buffer are the interesting
        // ones: each is a real object, so a careless unwrap would treat its
        // memory as a block algorithm rather than fail.
        const rejected: Array<unknown> = [
            new algorithm.Arcfour(),
            new mode.cbc.Cipher(keyed(0x07), iv),
            Buffer.alloc(16),
            {},
            null,
            42
        ];

        rejected.forEach(value => {

            expect(() => new mode.cbc.Cipher(value as never, iv))
                .toThrow(new RegExp('block algorithm', 'i'));
        });
    });

    it('does not retain algorithms once the modes using them are gone', () => {

        // The handle a mode holds must be released when the mode is collected,
        // or every mode ever built would pin its algorithm for the lifetime of
        // the process.
        const before = process.memoryUsage().heapUsed;

        for (let i = 0; i < 20000; i++) {
            new mode.cbc.Cipher(keyed(0x07), iv);
        }

        const growth = (process.memoryUsage().heapUsed - before) / 1048576;

        // Generous: this is checking for unbounded retention, not for a
        // particular allocator behaviour.
        expect(growth).toBeLessThan(200);
    });
});
