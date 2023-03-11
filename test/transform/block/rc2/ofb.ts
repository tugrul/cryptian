
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rc2 === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('RC2 transform ofb mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'efab29245e357f528250cd67dd9cf6c1671c54ed7fcfdc2121' +
        '54d4994e0485b4a88e2ae11cd6a3c5c5eef2ce2bc3cd06ee83', 'hex');

    const iv = Buffer.from('fed4174fca47ba7b', 'hex');


    const ciphertext = Buffer.from(
        '3ff41a03aca307592e227adab28577e4a285fe07e864725c34' +
        'c7fd1df620f22ddf6adde43c8d4397c37c7e6e4e4ad03fc586', 'hex');

    it('should encrypt', () => {
    
        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);

        const cipher = new mode.ofb.Cipher(rc2, iv);

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
        
        const decipher = new mode.ofb.Decipher(rc2, iv);

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

