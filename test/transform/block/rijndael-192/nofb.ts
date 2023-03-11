
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael192 === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip) ('rijndael-192 transform nofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'a986459a772c0cce4c1e5d58ca2fcd5114f2d2048400c1221d' +
        '676c259846b4e5e2f015b1c05a199fe84e2283a0a8f54dd9fe', 'hex');

    const iv = Buffer.from('21f88cc3e85fe561e9d8db2d17f3d2b6642192c81f337c60', 'hex');



    const ciphertext = Buffer.from(
        'b12fa29cfdfbe66289f1c4db2df39a4173c93e349dbc8de102' +
        'b1327f990e89f5a71d400e93682122f235fb1a5d319cc55020', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);

        const cipher = new mode.nofb.Cipher(rijndael, iv);

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
        
        const decipher = new mode.nofb.Decipher(rijndael, iv);

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

