
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rc2 === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip) ('RC2 transform nofb mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '8d770f57358ce8cd927e54e3bc131ec7f8436b22bd9d820618' +
        'e7c06223c8de27c093f362ec17b724f1669684d055f51a9460', 'hex');

    const iv = Buffer.from('f44387bb2ce68c04', 'hex');


    const ciphertext = Buffer.from(
        '7764301aa0fdcae49053a1176253455b3b9235a11b871290bb' +
        'e1ab74c47c2d1a33193bbb6b191e6ece8c367eb43a38712dae', 'hex');

    it('should encrypt', () => {
    
        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);

        const cipher = new mode.nofb.Cipher(rc2, iv);

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
        
        const decipher = new mode.nofb.Decipher(rc2, iv);

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

