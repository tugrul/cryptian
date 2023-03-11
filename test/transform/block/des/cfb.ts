
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Des === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip) ('des transform cfb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '82d81ef5fbb877e34de51eca192c30c17afa3293b5d1a8ec33' +
        '181cce295814d77cbd1ed3cc68d641b46205b92be3342bfaf2', 'hex');

    const iv = Buffer.from('8f45b675b98a45ad', 'hex');



    const ciphertext = Buffer.from(
        '5d24c9805733a81f1dbff5bc175ad6b7d775e36d2f25f85b67' +
        'c501c345eef6d5877e09aa3ad9c7fe7eb3676b7fccbdaea9d1', 'hex');

    it('should encrypt', () => {
    
        const des = new algorithm.Des();
        des.setKey(key);

        const cipher = new mode.cfb.Cipher(des, iv);

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

        const des = new algorithm.Des();
        des.setKey(key);

        const decipher = new mode.cfb.Decipher(des, iv);

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

