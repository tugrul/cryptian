
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael192 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('rijndael-192 transform cfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '49a2c43d21b5e57c97bd6ae309c3d9520ded89d52818ffc868' +
        '54ee668d5bd918d90ffff2b28511531417ad9b8dd0365847cc', 'hex');

    const iv = Buffer.from('c5da4e4260a1865257f7eee8ff91a27fff00f1f683cf8177', 'hex');



    const ciphertext = Buffer.from(
        '2ec295362bad0df138036383b1c8df7e3b356b7dd15f16a654' +
        '4e9246ef35d467bdc59dcdd3aea5cbc030f9d09ee33a591e30', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);

        const cipher = new mode.cfb.Cipher(rijndael, iv);

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

        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);
        
        const decipher = new mode.cfb.Decipher(rijndael, iv);

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

