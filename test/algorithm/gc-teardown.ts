
import {expect} from '@jest/globals';

import {execFileSync} from 'child_process';
import {resolve} from 'path';

// Node 24.19.0 added cleanup-hook calls to node::ObjectWrap: the constructor
// registers one with AddEnvironmentCleanupHook and the destructor removes it
// with RemoveEnvironmentCleanupHook. An addon object's destructor runs from a
// V8 weak callback with no context entered, so Environment::GetCurrent() is null
// and Node's own CHECK_NOT_NULL(env) aborts the whole process:
//
//   node::RemoveEnvironmentCleanupHook ... Assertion failed: (env) != nullptr
//   cryptian::AlgorithmStream<Arcfour>::~AlgorithmStream()
//
// It fired whenever a cryptian object was garbage collected on an affected Node,
// which meant any real program that made and dropped ciphers, and it was
// especially visible under test runners like Vitest that collect aggressively.
//
// The addon now extends Nan::ObjectWrap, whose destructor only resets the
// persistent handle and calls no cleanup hooks, so the null-env path cannot be
// reached. The crash only reproduces on Node 24.19+, so this cannot force the
// abort on every runner, but it exercises the exact path, construction, use and
// collection of many objects including the stream type from the report, and on
// an affected runtime a regression would abort this child and fail the test.
describe('objects can be garbage collected without aborting the process', () => {

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

    it('collects stream algorithms, the type in the crash report', () => {

        const output = runInChild(`
            for (let i = 0; i < 5000; i++) {
                const arcfour = new algorithm.Arcfour();
                arcfour.setKey(Buffer.alloc(16, i & 0xFF));
                arcfour.encrypt(Buffer.alloc(32, 0x41));
            }

            global.gc();
            global.gc();

            process.stdout.write('survived');
        `);

        expect(output).toBe('survived');
    });

    it('collects block algorithms', () => {

        const output = runInChild(`
            for (let i = 0; i < 5000; i++) {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(Buffer.alloc(16, i & 0xFF));
                rijndael.encrypt(Buffer.alloc(16, 0x41));
            }

            global.gc();
            global.gc();

            process.stdout.write('survived');
        `);

        expect(output).toBe('survived');
    });

    it('collects modes and their algorithms together', () => {

        const output = runInChild(`
            for (let i = 0; i < 3000; i++) {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(Buffer.alloc(16, 0x07));
                new mode.cbc.Cipher(rijndael, Buffer.alloc(16, 0x09)).transform(Buffer.alloc(16, 0x41));
            }

            global.gc();
            global.gc();
            global.gc();

            process.stdout.write('survived');
        `);

        expect(output).toBe('survived');
    });

    it('survives collection at process exit, when no context is entered', () => {

        // The abort in the report happened during teardown. Objects left live
        // at exit are collected with no context on the stack, which is the exact
        // condition that tripped the null-env assertion.
        const output = runInChild(`
            const live = [];

            for (let i = 0; i < 1000; i++) {
                const arcfour = new algorithm.Arcfour();
                arcfour.setKey(Buffer.alloc(16, i & 0xFF));
                live.push(arcfour);
            }

            process.stdout.write('reached exit with ' + live.length + ' live');
        `);

        expect(output).toBe('reached exit with 1000 live');
    });
});
