
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Gost === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip) ('gost transform nofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'f3e94f2abb09cf5d04883502a9be4a218e998cf0648fe7b581' +
        '50a609a86a47ef653a198179a249e1fb8aec896968b8429361', 'hex');

    const iv = Buffer.from('8511b495f5fc32a7', 'hex');


    const ciphertext = Buffer.from(
        '5734fdb1c42e33f220a79ada2670dd24498e427838b1b5ebc1' +
        'f2079a4661ee383661affe7b972214d873ab27e99174921143', 'hex');

    it('should encrypt', () => {
    
        const gost = new algorithm.Gost();
        gost.setKey(key);

        const cipher = new mode.nofb.Cipher(gost, iv);

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

        const decipher = new mode.nofb.Decipher(gost, iv);

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

