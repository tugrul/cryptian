
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Cast256 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip) ('cast-256 transform ncfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'ee4ab1883406bc98ca87d0e93f4745b29698de027a6d72def1' +
        '0a5bbf04ff85e65a357de2539825054c6c7375bce434b3446e', 'hex');

    const iv = Buffer.from('07fb5cddd30e8dcfcbf347214bfc5c0c', 'hex');



    const ciphertext = Buffer.from(
        '4058cdd0c44ae6b7dbc58d392b8f3aa011e1771cfa6bc602d6' +
        '6a07b168682cd7806c7dec4c97b5018b47b0f5c9a4da880e80', 'hex');

    it('should encrypt', () => {
    
        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);

        const cipher = new mode.ncfb.Cipher(cast256, iv);

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

        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);
        
        const decipher = new mode.ncfb.Decipher(cast256, iv);

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

