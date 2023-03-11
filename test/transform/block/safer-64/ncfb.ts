
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Safer === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip) ('safer-64 transform ncfb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '7b9259e818d9094bb0855d894c069601c1af2de257355089c0' +
        '6af6387b48e71dd2559cbe9d451c887486d88e92401fa6b2b3', 'hex');

    const iv = Buffer.from('e0d309268da3f0d7', 'hex');


    const ciphertext = Buffer.from(
        '9260b5d8b7ab5877bef4bb6eb6ab1e629e8ac650347cc8f494' +
        'a9296876ff989a7993954e581bdb7f32413341d1e92f4a4790', 'hex');

    it('should encrypt', () => {
    
        const safer = new algorithm.Safer();
        safer.setKey(key);

        const cipher = new mode.ncfb.Cipher(safer, iv);

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

        const safer = new algorithm.Safer();
        safer.setKey(key);

        const decipher = new mode.ncfb.Decipher(safer, iv);

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

