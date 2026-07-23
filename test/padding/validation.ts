
import {expect} from '@jest/globals';

import {padding} from '../..';
import {NotImplementedError} from '../../dist/error';
import Padding from '../../dist/padding';

// The counted padding schemes read the trailing byte as a length. A zero there
// used to pass every check, so unpad returned the chunk unchanged while
// reporting success and the caller received the padding as though it were
// plaintext.
describe('counted padding rejects a zero length byte', () => {

    const counted = [
        {name: 'Pkcs5', Padder: padding.Pkcs5, blockSize: 8},
        {name: 'Pkcs7', Padder: padding.Pkcs7, blockSize: 16},
        {name: 'AnsiX923', Padder: padding.AnsiX923, blockSize: 16},
        {name: 'Iso10126', Padder: padding.Iso10126, blockSize: 16}
    ];

    counted.forEach(({name, Padder, blockSize}) => {

        describe(name, () => {

            const padder = new Padder(blockSize);

            it('throws when the trailing byte is zero', () => {

                const chunk = Buffer.alloc(blockSize, 0);

                expect(() => padder.unpad(chunk)).toThrow();
            });

            it('throws when the count exceeds the block size', () => {

                const chunk = Buffer.alloc(blockSize, 0);
                chunk[chunk.length - 1] = blockSize + 1;

                expect(() => padder.unpad(chunk)).toThrow();
            });

            it('round trips ordinary data', () => {

                const plaintext = Buffer.from('cryptian');

                const padded = padder.pad(plaintext);

                expect(padded.length % blockSize).toBe(0);
                expect(padder.unpad(padded).equals(plaintext)).toBe(true);
            });

            it('round trips data that exactly fills a block', () => {

                const plaintext = Buffer.alloc(blockSize, 0x41);

                const padded = padder.pad(plaintext);

                // A full block of padding is appended so the length byte is
                // always present and unambiguous.
                expect(padded.length).toBe(blockSize * 2);
                expect(padder.unpad(padded).equals(plaintext)).toBe(true);
            });
        });

    });

});

// The verification loop stopped one byte short, so the deepest padding byte was
// never compared and corrupt padding could pass.
describe('Pkcs5 verifies every padding byte', () => {

    const padder = new padding.Pkcs5(8);

    it('throws when the deepest padding byte is wrong', () => {

        const chunk = Buffer.alloc(8, 0x41);

        // Four bytes of padding, but the first one is corrupt.
        chunk[4] = 0xFF;
        chunk[5] = 4;
        chunk[6] = 4;
        chunk[7] = 4;

        expect(() => padder.unpad(chunk)).toThrow(/Padding byte array not same/);
    });

    it('accepts padding where every byte agrees', () => {

        const chunk = Buffer.alloc(8, 0x41);

        chunk[4] = 4;
        chunk[5] = 4;
        chunk[6] = 4;
        chunk[7] = 4;

        expect(padder.unpad(chunk).length).toBe(4);
    });
});

describe('NotImplementedError', () => {

    it('reports its own name', () => {

        const error = new NotImplementedError('not done');

        expect(error.name).toBe('NotImplementedError');
        expect(error.message).toBe('not done');
    });

    it('is recognised by instanceof', () => {

        const error = new NotImplementedError('not done');

        expect(error).toBeInstanceOf(NotImplementedError);
        expect(error).toBeInstanceOf(Error);
    });

    it('is thrown by the padding base class', () => {

        const base = new Padding(8);

        expect(() => base.pad(Buffer.alloc(0))).toThrow(NotImplementedError);
        expect(() => base.unpad(Buffer.alloc(0))).toThrow(NotImplementedError);
    });
});
