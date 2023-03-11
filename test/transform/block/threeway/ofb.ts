
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Threeway === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip) ('threeway transform ofb mode', () => {

    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '92fe4f2acda55a78d6cad2e2d4962bd9a4228ce3220ee9a2f2' +
        '166bb80d0629ab7828307459372ca2d3702de39137c99e7a95', 'hex');

    const iv = Buffer.from('5fab03c5c9b408a68ef9151b', 'hex');



    const ciphertext = Buffer.from(
        '6d94aefe1195d47c7f2fee89ddcc7a984923553f65de3e02b6' +
        '68a2e961bc22ae037184bf4d51ecde200338714da0e39580dc', 'hex');

    it('should encrypt', () => {
    
        const threeway = new algorithm.Threeway();
        threeway.setKey(key);

        const cipher = new mode.ofb.Cipher(threeway, iv);

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
        
        const decipher = new mode.ofb.Decipher(threeway, iv);

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

