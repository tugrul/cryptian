
import {expect} from '@jest/globals';

import {default as cryptian, BlockAlgorithmList, StreamAlgorithmList} from '../..';

const {algorithm, mode} = cryptian;

// Calling a wrapped constructor without new redirected through the stored
// constructor with Nan::NewInstance(...).ToLocalChecked(). On current V8 that
// re-entrant NewInstance, on a template that uses Inherit, can return an empty
// MaybeLocal, and ToLocalChecked on empty is a fatal process abort:
//
//   FATAL ERROR: v8::ToLocalChecked Empty MaybeLocal
//
// The redirect now checks the MaybeLocal and reports an ordinary error instead
// of aborting, so a missing new can never take the process down. Where V8 does
// allow the redirect, it still returns a usable instance.
describe('constructors called without new do not abort the process', () => {

    it('block algorithms either construct or throw, never crash', () => {

        const withoutNew = algorithm.Rijndael128 as unknown as (...args: Array<unknown>) => unknown;

        let outcome: unknown;

        expect(() => {
            try {
                outcome = withoutNew();
            } catch {
                outcome = 'threw';
            }
        }).not.toThrow();

        // Reaching this line at all means the process was not aborted. On V8
        // versions that permit the redirect the result is a working instance.
        if (outcome !== 'threw') {
            const instance = outcome as InstanceType<typeof algorithm.Rijndael128>;
            expect(instance.getBlockSize()).toBe(16);
        }
    });

    it('stream algorithms either construct or throw, never crash', () => {

        const withoutNew = algorithm.Arcfour as unknown as (...args: Array<unknown>) => unknown;

        let outcome: unknown;

        try {
            outcome = withoutNew();
        } catch {
            outcome = 'threw';
        }

        if (outcome !== 'threw') {
            const instance = outcome as InstanceType<typeof algorithm.Arcfour>;
            instance.setKey(Buffer.alloc(16, 0x01));
            expect(instance.encrypt(Buffer.alloc(8, 0x41)).length).toBe(8);
        }
    });

    it('modes either construct or throw, never crash', () => {

        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(Buffer.alloc(16, 0x01));

        const withoutNew = mode.cbc.Cipher as unknown as (...args: Array<unknown>) => unknown;

        let outcome: unknown;

        try {
            outcome = withoutNew(rijndael, Buffer.alloc(16, 0x02));
        } catch {
            outcome = 'threw';
        }

        if (outcome !== 'threw') {
            const instance = outcome as InstanceType<typeof mode.cbc.Cipher>;
            expect(instance.getBlockSize()).toBe(16);
        }
    });

    it('covers every exported constructor', () => {

        // Guards against a new algorithm or mode being added with the raw
        // ToLocalChecked pattern that this fixed.
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(Buffer.alloc(16, 0x01));
        const iv = Buffer.alloc(16, 0x02);

        const call = (fn: unknown, args: Array<unknown>) => {
            try {
                (fn as (...a: Array<unknown>) => unknown)(...args);
            } catch {
                // A throw is a fine outcome; a crash would have aborted the run.
            }
        };

        Object.values(BlockAlgorithmList).forEach(name => call(algorithm[name], []));
        Object.values(StreamAlgorithmList).forEach(name => call(algorithm[name], []));

        (['cbc', 'pcbc', 'cfb', 'ncfb', 'ofb', 'nofb', 'ctr', 'ecb'] as const).forEach(name => {
            call(mode[name].Cipher, [rijndael, iv]);
            call(mode[name].Decipher, [rijndael, iv]);
        });

        // If the process is still alive to make this assertion, none aborted.
        expect(true).toBe(true);
    });
});
