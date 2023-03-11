
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Gost === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('gost transform cfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '5e05cc00268b2d4fb895cc550b517f8556028c106aae745898' +
        'ebf91be62038515318f4d3b220bc52ae4147248faf0befc568', 'hex');

    const iv = Buffer.from('b9481b3e760f3fe1', 'hex');


    const ciphertext = Buffer.from(
        '075ce0e32b3423736dc9496b8eed9d09b453d67293af9de7c7' +
        'a1fa487324f90665f7b90db511c39e32a6368eeaf50ace8efd', 'hex');

    it('should encrypt', () => {
    
        const gost = new algorithm.Gost();
        gost.setKey(key);

        const cipher = new mode.cfb.Cipher(gost, iv);

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

        const decipher = new mode.cfb.Decipher(gost, iv);

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

