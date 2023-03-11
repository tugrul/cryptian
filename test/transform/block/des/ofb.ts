

import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Des === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip) ('des transform ofb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '20643d16aca11239c49be9e7b779d4ed414b055e5775004ce0' +
        'acf530d9dd608e81f88165bb5e0b4a7ec5fab6880faeac4d1e', 'hex');

    const iv = Buffer.from('126dc9e2ef8837a6', 'hex');



    const ciphertext = Buffer.from(
        'dab33a5e88132674401affd08ebdec18047bf9dd867ece9105' +
        'bbe76aa6a871c34bd404fc36ac9b103f0192e897bb3707c58a', 'hex');

    it('should encrypt', () => {
    
        const des = new algorithm.Des();
        des.setKey(key);

        const cipher = new mode.ofb.Cipher(des, iv);

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

        const des = new algorithm.Des();
        des.setKey(key);

        const decipher = new mode.ofb.Decipher(des, iv);

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

