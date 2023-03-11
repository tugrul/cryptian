
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael128 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('rijndael-128 transform ncfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'a74fefda0c363f7c020cbb905c9d57c264f3c8312892ea2d7f' +
        '35d574cc880fe101cf713a298472e4d76c831f1421789332bc', 'hex');

    const iv = Buffer.from('8451109c86aa4cc8417b958a703c3c11', 'hex');



    const ciphertext = Buffer.from(
        '7937991816ea8c40520211adac0ac92ce73321d58b23e42eec' +
        '481e17996e1150819964dd4d2975c56479a32b1bb60893eae9', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(key);

        const cipher = new mode.ncfb.Cipher(rijndael, iv);

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

        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(key);
        
        const decipher = new mode.ncfb.Decipher(rijndael, iv);

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

