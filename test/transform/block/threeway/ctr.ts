
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Threeway === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip) ('threeway transform ctr mode', () => {

    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'a910ae0d5d3377dc71e5122e5af6d62f7becaee7319656c030' +
        '18d977feb4b14d8d5a3a7e64a521a3bedb8d0b625bac61fd38', 'hex');

    const iv = Buffer.from('9bcda875a38d8e925cd91fdc', 'hex');



    const ciphertext = Buffer.from(
        '7519c7bd500fc83384c709f0bb1601dab35073808553eaa320' +
        '900948772bb186332e687d444d12796968229679604f1eb73b', 'hex');

    it('should encrypt', () => {
    
        const threeway = new algorithm.Threeway();
        threeway.setKey(key);

        const cipher = new mode.ctr.Cipher(threeway, iv);

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

        const threeway = new algorithm.Threeway();
        threeway.setKey(key);
        
        const decipher = new mode.ctr.Decipher(threeway, iv);

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

