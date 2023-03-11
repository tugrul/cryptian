

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Loki97 === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('loki97 transform ctr mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'c0a1ce67a973b30a5c607a7dec9587546c50f561d9018df518' +
        '25e6f22e3020af3e7a48a3d3ff9cc1b6700b98975e43da4e46', 'hex');

    const iv = Buffer.from('c7cead535387f7fd6ba87c3d0d795e51', 'hex');


    const ciphertext = Buffer.from(
        '862fcfc1cf0b75db9e1b7d2d421ba441861bec7306e3ef2586' +
        '6aa4c37c0b0fb51b834ea0a6f3e1bd1a0ecfa1cf5f263b4e56', 'hex');

    it('should encrypt', () => {
    
        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);

        const cipher = new mode.ctr.Cipher(loki97, iv);

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

        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);
        
        const decipher = new mode.ctr.Decipher(loki97, iv);

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

