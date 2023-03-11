
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Saferplus === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip) ('saferplus transform cfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '7f1076ac1ac44aac8f9f86bded6058eacc08c8bfc26a5f2597' +
        'cd0cf45b67223d95f9e53f56ba230ec1dade3d1384afc9752f', 'hex');

    const iv = Buffer.from('6dc2edcf565c955a5abf670a1e4f6103', 'hex');



    const ciphertext = Buffer.from(
        '569a45e683eef7fd0880eb5776a49378b351d427d23af0a643' +
        '22cf3abca72e1cd3954f683c8da030c699769c8bde2ceabdd6', 'hex');

    it('should encrypt', () => {
    
        const saferplus = new algorithm.Saferplus();
        saferplus.setKey(key);

        const cipher = new mode.cfb.Cipher(saferplus, iv);

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

        const saferplus = new algorithm.Saferplus();
        saferplus.setKey(key);
        
        const decipher = new mode.cfb.Decipher(saferplus, iv);

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

