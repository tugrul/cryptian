
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Threeway === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip) ('threeway transform nofb mode', () => {

    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '2da7ca9930bc420a518e526c6d572eed157f653ad6d7881fff' +
        '2956c7cc1c220352d464af1cbe5d927793bec256c5960cc4d0', 'hex');

    const iv = Buffer.from('e95bcd47ac049a21140cc2e0', 'hex');



    const ciphertext = Buffer.from(
        'd6b6e43c047cd7b3e63dbfcf8ed51db9535de51a94ab2a3b55' +
        '00b57ce71fc88ba82df1d2141d09dbe612b0f260a6a3af8fbb', 'hex');

    it('should encrypt', () => {
    
        const threeway = new algorithm.Threeway();
        threeway.setKey(key);

        const cipher = new mode.nofb.Cipher(threeway, iv);

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

        const threeway = new algorithm.Threeway();
        threeway.setKey(key);
        
        const decipher = new mode.nofb.Decipher(threeway, iv);

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

