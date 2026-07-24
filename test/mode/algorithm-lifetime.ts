
import {expect} from '@jest/globals';

import {execFileSync} from 'child_process';
import {resolve} from 'path';

// A mode holds a raw pointer to the algorithm's C++ object. Nothing kept the
// algorithm's JavaScript object reachable, so once it was collected the pointer
// dangled and using the mode killed the process with a segmentation fault.
//
// It was reachable from ordinary code. Passing a freshly constructed algorithm
// straight into a mode leaves no reference to it anywhere:
//
//   new mode.cbc.Cipher(new algorithm.Rijndael128(), iv)
//
// Existing tests never hit it because they all keep the algorithm in a local
// variable for the length of the test, which is exactly what stops it being
// collected.
//
// Collection cannot be forced from inside the test runner, so this runs in a
// child process started with --expose-gc. A failure here is a crash rather than
// a wrong value, so the assertion is on the exit status.
describe('a mode keeps its algorithm alive', () => {

    const entry = resolve(__dirname, '../..');

    const runInChild = (body: string) => {

        const source = `
            const {default: {algorithm, mode}} = require(${JSON.stringify(entry)});
            ${body}
        `;

        return execFileSync(process.execPath, ['--expose-gc', '-e', source], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        });
    };

    it('survives collection of an algorithm passed inline', () => {

        const output = runInChild(`
            const iv = Buffer.alloc(16, 9);

            const build = () => {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(Buffer.alloc(16, 7));
                return rijndael;
            };

            const cipher = new mode.cbc.Cipher(build(), iv);

            global.gc();
            global.gc();
            global.gc();

            process.stdout.write(cipher.transform(Buffer.alloc(16, 0x41)).toString('hex'));
        `);

        // The same key and vector through an algorithm that was never at risk.
        expect(output).toBe('e1bbdff7e066749e7d963b68b237173d');
    });

    it('survives collection across many modes at once', () => {

        const output = runInChild(`
            const iv = Buffer.alloc(16, 9);
            const ciphers = [];

            for (let i = 0; i < 200; i++) {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(Buffer.alloc(16, 7));
                ciphers.push(new mode.cbc.Cipher(rijndael, iv));
            }

            global.gc();
            global.gc();

            const results = new Set(ciphers.map(c => c.transform(Buffer.alloc(16, 0x41)).toString('hex')));

            process.stdout.write(String(results.size));
        `);

        // Every mode was built from the same key and vector, so one result.
        expect(output).toBe('1');
    });

    it('survives collection of the mode itself', () => {

        const output = runInChild(`
            const iv = Buffer.alloc(16, 9);

            for (let i = 0; i < 200; i++) {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(Buffer.alloc(16, 7));
                new mode.cbc.Cipher(rijndael, iv).transform(Buffer.alloc(16, 0x41));
            }

            global.gc();
            global.gc();

            process.stdout.write('survived');
        `);

        expect(output).toBe('survived');
    });
});
