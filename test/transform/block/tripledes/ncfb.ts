
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Tripledes === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip) ('tripledes transform ncfb mode', () => {

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    const plaintext = Buffer.from(
        '23c14ff2285a91aa935b9e354620a7d4aec57211d9fb794427' +
        '07aa150522f42b5560c8317a663bf37e799cd89941ab5830df', 'hex');

    const iv = Buffer.from('aa536f75f2ffb256', 'hex');



    const ciphertext = Buffer.from(
        '2a2b7f275bb382749a66809f46210047f38910c3a6d33901ab' +
        '7941f06db018fdd333a86b43a5857eff7bed09f6136ce7ba77', 'hex');

    it('should encrypt', () => {

        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const cipher = new mode.ncfb.Cipher(tripledes, iv);

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

        const decipher = new mode.ncfb.Decipher(tripledes, iv);

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

