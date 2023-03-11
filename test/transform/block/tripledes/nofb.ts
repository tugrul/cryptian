
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Tripledes === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip)
('tripledes transform nofb mode', () => {

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    const plaintext = Buffer.from(
        '99b421a2ae3018a7b1ea0f066540991383070fa6a8977945a5' +
        'f9e591bcf69de1aae225d938fff82326914d7ae042af65ae4c', 'hex');

    const iv = Buffer.from('c82f539cf9a0cf1b', 'hex');



    const ciphertext = Buffer.from(
        '32af47b3d14754c5d1a527d40b375f1e5452f59609b9f7556d' +
        'f6e60dc5646debfaeca84035639e39329b30003656c039a9bc', 'hex');

    it('should encrypt', () => {

        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const cipher = new mode.nofb.Cipher(tripledes, iv);

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

        const decipher = new mode.nofb.Decipher(tripledes, iv);

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

