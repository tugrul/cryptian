
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Cast128 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip) ('cast-128 transform ncfb mode', () => {


    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '9907d61dcfc9456b237d002ce859b5a1d7bc92747b9cc9d76e' +
        '968442060fa16c9a2f3dd1d2205e19a92c2ad56d12e927224e', 'hex');

    const iv = Buffer.from('8f45b675b98a45ad', 'hex');


    const ciphertext = Buffer.from(
        '0945137cff02b5decb232bfeaddf0256f5a392a77f9bca91c6' +
        '8d2a925540cf0e2db9ca9b02acbeab6c427b94e75d1d70adc2', 'hex');

    it('should encrypt', () => {
    
        const cast128 = new algorithm.Cast128();
        cast128.setKey(key);

        const cipher = new mode.ncfb.Cipher(cast128, iv);

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

        const cast128 = new algorithm.Cast128();
        cast128.setKey(key);

        const decipher = new mode.ncfb.Decipher(cast128, iv);

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

