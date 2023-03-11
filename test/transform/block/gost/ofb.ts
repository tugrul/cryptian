
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Gost === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip) ('gost transform ofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '9786db706aa1e107198b0f1cfdbc66172633a1adfacbb1e1fd' +
        'b0e921c2b5a1537f03c9b9360e0cafa9df2fe2cf7c32771003', 'hex');

    const iv = Buffer.from('d8938db207db4d34', 'hex');


    const ciphertext = Buffer.from(
        '341a797858d93a9f157336a0276cf3cd26afa4902faf1c9ad8' +
        'f0ed20bf6a3dd8f36a1c0759bce523f998829f485e1b63941b', 'hex');

    it('should encrypt', () => {
    
        const gost = new algorithm.Gost();
        gost.setKey(key);

        const cipher = new mode.ofb.Cipher(gost, iv);

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

        const gost = new algorithm.Gost();
        gost.setKey(key);

        const decipher = new mode.ofb.Decipher(gost, iv);

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

