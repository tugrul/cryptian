
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Gost === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip) ('gost transform ncfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '9a6e24b5345b9d74868b550f644642ec6a899adac3d2c6f6eb' +
        '48bab675a23e435681a79d144ec657c2d38a2165714fd31756', 'hex');

    const iv = Buffer.from('25646f5ab8dd5af6', 'hex');


    const ciphertext = Buffer.from(
        '348a6b908e57e0be95e6d632e11a95b470299b8ce407706f78' +
        '191dee7fa51690eac6b3f13be3daa472b6084cb2bbd33b033d', 'hex');

    it('should encrypt', () => {
    
        const gost = new algorithm.Gost();
        gost.setKey(key);

        const cipher = new mode.ncfb.Cipher(gost, iv);

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

        const gost = new algorithm.Gost();
        gost.setKey(key);

        const decipher = new mode.ncfb.Decipher(gost, iv);

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

