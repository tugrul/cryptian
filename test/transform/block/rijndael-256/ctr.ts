
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael256 === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip) ('rijndael-256 transform ctr mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'd33f9997796d515b285ec6f72b54510d04712b2c27fe6115e4' +
        '51606617fff2dc6eee42a5ea7495c9a89021f20421b39d52a6', 'hex');

    const iv = Buffer.from('87983ae9db984b34132efe4e8fff525d8e3d620f078653af85a861437f5c26e4', 'hex');


    const ciphertext = Buffer.from(
        '7fd294c4ef0688de162e74dede722696f46e1f56a380d7d8d5' +
        '4b101f7dfd5eed34df824155cf3942d502eaf4045e206ddd0c', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael256();
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

        const rijndael = new algorithm.Rijndael256();
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

