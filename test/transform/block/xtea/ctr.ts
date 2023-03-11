
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Xtea === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('xtea transform ctr mode', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '2deeeb1c5267c36c5122386afb84e103cdc766e34a340c7689' +
        '32af04e815fe3a322469d543e1df03790276379dc1d1f2e49c', 'hex');

    const iv = Buffer.from('60ada3358e80e6f3', 'hex');



    const ciphertext = Buffer.from(
        'd1270ef55b2331a5b32459d29ff05bf284bd2e77ac39bac46a' +
        '81768c17fe825af917025bdd02f98192a9433fc24badeaefce', 'hex');

    it('should encrypt', () => {
    
        const xtea = new algorithm.Xtea();
        xtea.setKey(key);

        const cipher = new mode.ctr.Cipher(xtea, iv);

        const transform = createEncryptStream(cipher);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

        buffer.on('finish', () => {
            const contents = buffer.getContents();

            expect(contents).toBeTruthy();

            if (contents !== false) {
                assert(ciphertext.equals(contents), 'encrypted plaintext should be equal to ciphertext');
            }
        });

        transform.write(plaintext.slice(0, 22));
        transform.write(plaintext.slice(22, 39));
        transform.end(plaintext.slice(39));
        
    });

    it('should decrypt', () => {

        const xtea = new algorithm.Xtea();
        xtea.setKey(key);

        const decipher = new mode.ctr.Decipher(xtea, iv);

        const transform = createDecryptStream(decipher);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

        buffer.on('finish', () => {
            const contents = buffer.getContents();

            expect(contents).toBeTruthy();

            if (contents !== false) {
                assert(plaintext.equals(contents), 'decrypted ciphertext should be equal to plaintext');
            }
        });

        transform.write(ciphertext.slice(0, 27));
        transform.write(ciphertext.slice(27, 42));
        transform.end(ciphertext.slice(42));
        
    });

    

});

