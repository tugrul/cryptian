
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael192 === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('rijndael-192 transform ctr mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '6a3cc37e686b10272ca4f6a099dd565cc72035186c8844a4b9' +
        '7bb5117bb7dc59b39a76209207d4f749ec4bd4e6edd55aae24', 'hex');

    const iv = Buffer.from('56a00deaa1470cac2727f64012ea919773bae00bdd9a3b08', 'hex');



    const ciphertext = Buffer.from(
        'ba9aa30038e8a027fd3d462e7a04a963a45da4cd8b6a9e6c26' +
        'c6a7ae634ff7334c4605e2a005669f9eb90cf46727fc0335d3', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);

        const cipher = new mode.ctr.Cipher(rijndael, iv);

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
        
        const decipher = new mode.ctr.Decipher(rijndael, iv);

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

