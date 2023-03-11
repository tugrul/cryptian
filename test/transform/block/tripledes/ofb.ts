
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';
(typeof algorithm.Tripledes === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip) ('tripledes transform ofb mode', () => {

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    const plaintext = Buffer.from(
        'a45ef9cf78c1c899d5cca51c6c9d7da0b6d762dafc754465cf' +
        'ad81e686aeed3307997c35c95b2115c906c2f141ed8dd97a2f', 'hex');

    const iv = Buffer.from('db99f13230b95026', 'hex');



    const ciphertext = Buffer.from(
        '5e5b7c21912bbc36d2e22965595fca05cea83612c2181cf21c' +
        'd88d10db71b4043c418619efb7db22c2f98d3d8464af04abd1', 'hex');

    it('should encrypt', () => {

        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const cipher = new mode.ofb.Cipher(tripledes, iv);

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

        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const decipher = new mode.ofb.Decipher(tripledes, iv);

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

