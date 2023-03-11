
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael192 === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('rijndael-192 transform ofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'f0e45297307860b79cb89492997917e6a6d9ee73d31972646a' +
        '80f5364d0ed1b9c54c171eb35c55177813d0b02f8a7765bfe3', 'hex');

    const iv = Buffer.from('1dc4771207aaf74f15e3baf06b9a21fec489224c56407d0c', 'hex');



    const ciphertext = Buffer.from(
        'd8fc1bef932fd7ae4ca61dbcf4607bb6a2469bf4016e0aaa3b' +
        '8eac6b2a972f0475259622fe48bc5ad8a9fe25fbe5a2c07da1', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);

        const cipher = new mode.ofb.Cipher(rijndael, iv);

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

        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);
        
        const decipher = new mode.ofb.Decipher(rijndael, iv);

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

