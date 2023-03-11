
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rc2 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip) ('RC2 transform cfb mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '822d3654ae7d895c9bfc1c35aa48d7f15c5c7ab4ea2dbfe21d' +
        '478fe6d53f1f0f7eb8d364df48d636b6f87831b364f68075ef', 'hex');

    const iv = Buffer.from('27494785ef81c431', 'hex');


    const ciphertext = Buffer.from(
        '77b78298e82299f8310680b02a5594669fc0623e8478b3428d' +
        '61a3c0bb262dae9ce83a37d3c7589cd3eea7e0a15ab43b7847', 'hex');

    it('should encrypt', () => {
    
        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);

        const cipher = new mode.cfb.Cipher(rc2, iv);

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

        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);
        
        const decipher = new mode.cfb.Decipher(rc2, iv);

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

