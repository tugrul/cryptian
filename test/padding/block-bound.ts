
import {expect} from '@jest/globals';

import {padding} from '../..';
import Padding from '../../dist/padding';

// Padding never exceeds one block, whichever scheme is in use, so no unpad has
// any reason to remove more than that. The schemes that record a length reject
// a count larger than the block, and the filler schemes stop scanning once they
// have walked back a block.
//
// The bound matters most for Null and Space, which record no length at all. If
// the scan were unbounded, plaintext that genuinely ended in filler would lose
// an unbounded run of its own bytes rather than at most one block. It cannot be
// made lossless, since the schemes carry no length, but the damage stays
// bounded and the caller keeps the ability to reason about the worst case.
//
// This is asserted for every padding so a later refactor cannot quietly drop it
// from one of them.
describe('unpad never consumes more than one block', () => {

    const blockSize = 8;

    const schemes = [
        {name: 'Null', padder: new padding.Null(blockSize)},
        {name: 'Space', padder: new padding.Space(blockSize)},
        {name: 'Pkcs5', padder: new padding.Pkcs5(blockSize)},
        {name: 'Pkcs7', padder: new padding.Pkcs7(blockSize)},
        {name: 'AnsiX923', padder: new padding.AnsiX923(blockSize)},
        {name: 'Iso7816', padder: new padding.Iso7816(blockSize)},
        {name: 'Iso10126', padder: new padding.Iso10126(blockSize)}
    ];

    // Inputs chosen to tempt an unbounded scan: long runs of filler with no
    // boundary to stop at, and trailing bytes that could be read as an
    // oversized length.
    const hostile = [
        {name: 'a long run of zero bytes', chunk: Buffer.alloc(512, 0x00)},
        {name: 'a long run of spaces', chunk: Buffer.alloc(512, 0x20)},
        {name: 'a long run of 0xff', chunk: Buffer.alloc(512, 0xFF)},
        {name: 'zeros behind a single marker', chunk: Buffer.concat([Buffer.from([0x80]), Buffer.alloc(511, 0x00)])},
        {name: 'a trailing byte larger than the block', chunk: Buffer.concat([Buffer.alloc(511, 0x41), Buffer.from([0xFF])])}
    ];

    schemes.forEach(({name, padder}) => {

        describe(name, () => {

            hostile.forEach(({name: inputName, chunk}) => {

                it('keeps at least length minus one block given ' + inputName, () => {

                    let result: Buffer;

                    try {
                        result = padder.unpad(chunk);
                    } catch (error) {
                        // Refusing the input is a valid outcome. What is not
                        // valid is silently eating more than a block.
                        return;
                    }

                    expect(result.length).toBeGreaterThanOrEqual(chunk.length - blockSize);
                });

            });

            it('round trips data that ends in filler bytes within the bound', () => {

                // Plaintext whose own last bytes look like padding. Filler
                // schemes cannot recover this exactly, which is inherent to
                // carrying no length, but the loss stays inside one block.
                const plaintext = Buffer.concat([Buffer.from('data'), Buffer.alloc(12, 0x00)]);

                let recovered: Buffer;

                try {
                    recovered = padder.unpad(padder.pad(plaintext));
                } catch (error) {
                    return;
                }

                expect(recovered.length).toBeGreaterThanOrEqual(plaintext.length - blockSize);
                expect(recovered.length).toBeLessThanOrEqual(plaintext.length);

                // Whatever survives must be a prefix of the original.
                expect(plaintext.subarray(0, recovered.length).equals(recovered)).toBe(true);
            });

            it('round trips ordinary data exactly', () => {

                const plaintext = Buffer.from('ordinary payload');

                expect(padder.unpad(padder.pad(plaintext)).equals(plaintext)).toBe(true);
            });

        });

    });

    it('covers every padding the package exports', () => {

        const exported = Object.keys(padding).filter(key => {
            const candidate = (padding as Record<string, unknown>)[key];
            return typeof candidate === 'function' && candidate !== Padding;
        });

        const covered = schemes.map(({name}) => name);

        // A new padding added without a bound should fail here rather than
        // slipping through untested.
        expect(covered.sort()).toEqual(exported.sort());
    });

});
