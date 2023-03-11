
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Safer === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip) ('safer-64 transform nofb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '3f4a241c06634db5738de617ae2f0c7a823f89a877f578b1c2' +
        '716aff1fc405f5fce81268788a9ae1fc15ec5c8c33d5e51c97', 'hex');

    const iv = Buffer.from('c62dad5c93e44aa4', 'hex');


    const ciphertext = Buffer.from(
        '8a49630ecd41a923c9d3cd7a04a3944793f0dd8423ff167833' +
        'c97234d29832afda04bf5b3e92bff3f22091802c17eebeea55', 'hex');

    it('should encrypt', () => {
    
        const safer = new algorithm.Safer();
        safer.setKey(key);

        const cipher = new mode.nofb.Cipher(safer, iv);

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

        const safer = new algorithm.Safer();
        safer.setKey(key);

        const decipher = new mode.nofb.Decipher(safer, iv);

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

