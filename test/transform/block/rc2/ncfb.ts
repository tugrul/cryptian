
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rc2 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('RC2 transform ncfb mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '291410de8706ee7bdffa07bb71143c8f06e89f16f10be34c8e' +
        'ac5979e5eab63831a2e27f4792fd383086a8f8dfc41a14e9b5', 'hex');

    const iv = Buffer.from('f10a46bd7d64a88d', 'hex');


    const ciphertext = Buffer.from(
        '658ee9fef613eaa84dbd2d27ca324a56c40f48a06d0170f979' +
        'aa96f1e13f213ed96cc4757dd1f9ae92a1b1454948d9055dce', 'hex');

    it('should encrypt', () => {
    
        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);

        const cipher = new mode.ncfb.Cipher(rc2, iv);

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

        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);
        
        const decipher = new mode.ncfb.Decipher(rc2, iv);

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

