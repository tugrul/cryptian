
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// Throwing from the addon schedules a JavaScript exception but does not unwind
// C++. Every guard therefore has to return as well. Where it did not, a
// rejected call still ran the rest of the method: a setKey that threw replaced
// the key with an empty one and rebuilt the schedule from it, so an instance
// that had been given a good key silently began encrypting under a key the
// caller never chose.
describe('rejected arguments leave the object unchanged', () => {

    const key = Buffer.alloc(16, 0x01);

    const fingerprint = (rijndael: InstanceType<typeof algorithm.Rijndael128>) =>
        new mode.ecb.Cipher(rijndael, Buffer.alloc(0))
            .transform(Buffer.alloc(16, 0x41))
            .toString('hex');

    const keyed = () => {
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(key);
        return rijndael;
    };

    // Values that are neither a Buffer nor a string.
    const rejected: Array<[string, unknown]> = [
        ['a number', 12345],
        ['null', null],
        ['a plain object', {}],
        ['an array', [1, 2, 3]],
        ['a boolean', true]
    ];

    describe('setKey', () => {

        it('throws when called with no argument and keeps the key', () => {

            const rijndael = keyed();
            const before = fingerprint(rijndael);

            expect(() => (rijndael as unknown as {setKey: () => void}).setKey())
                .toThrow(/Missing parameter/);

            expect(fingerprint(rijndael)).toBe(before);
        });

        rejected.forEach(([name, value]) => {

            it('throws for ' + name + ' and keeps the key', () => {

                const rijndael = keyed();
                const before = fingerprint(rijndael);

                expect(() => rijndael.setKey(value as Buffer)).toThrow();

                expect(fingerprint(rijndael)).toBe(before);
            });
        });

        it('accepts a string as well as a buffer', () => {

            const fromString = new algorithm.Rijndael128();
            fromString.setKey('0123456789abcdef');

            const fromBuffer = new algorithm.Rijndael128();
            fromBuffer.setKey(Buffer.from('0123456789abcdef'));

            expect(fingerprint(fromString)).toBe(fingerprint(fromBuffer));
        });
    });

    describe('encrypt and decrypt', () => {

        it('throw when called with no argument', () => {

            const rijndael = keyed();

            expect(() => (rijndael as unknown as {encrypt: () => void}).encrypt())
                .toThrow(/Missing parameter/);
            expect(() => (rijndael as unknown as {decrypt: () => void}).decrypt())
                .toThrow(/Missing parameter/);
        });

        rejected.forEach(([name, value]) => {

            it('throw for ' + name, () => {

                const rijndael = keyed();

                expect(() => rijndael.encrypt(value as Buffer)).toThrow();
                expect(() => rijndael.decrypt(value as Buffer)).toThrow();
            });
        });
    });

    describe('mode construction', () => {

        rejected.forEach(([name, value]) => {

            it('rejects ' + name + ' as an iv', () => {

                expect(() => new mode.cbc.Cipher(keyed(), value as Buffer)).toThrow();
            });
        });

        // ECB accepts an empty vector, so before the conversion result was
        // checked a bad iv produced a working object with an exception pending.
        it('rejects a bad iv for ecb even though ecb takes an empty one', () => {

            expect(() => new mode.ecb.Cipher(keyed(), 12345 as unknown as Buffer)).toThrow();
        });
    });

    describe('transform', () => {

        rejected.forEach(([name, value]) => {

            it('rejects ' + name, () => {

                const cipher = new mode.cbc.Cipher(keyed(), Buffer.alloc(16, 0x02));

                expect(() => cipher.transform(value as Buffer)).toThrow();
            });
        });

        it('throws when called with no argument', () => {

            const cipher = new mode.cbc.Cipher(keyed(), Buffer.alloc(16, 0x02));

            expect(() => (cipher as unknown as {transform: () => void}).transform())
                .toThrow(/Missing parameter/);
        });
    });
});
