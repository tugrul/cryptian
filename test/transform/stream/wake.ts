
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../..";

const {algorithm} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Wake === 'function' ? describe : describe.skip)
('wake transform', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = (i * 5 + 10) & 0xff;
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('434d575db053acfe6e4076f05298bedbd5f4f000be555d029b1367cffc7cd51bba61c76aa17da3530fb7d9', 'hex');
    const plaintext  = Buffer.from('05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f', 'hex');

    it('should encrypt', () => {
        const wake = new algorithm.Wake();
        wake.setKey(key);

        const transform = createEncryptStream(wake);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
        
        buffer.on('finish', () => {
            const contents = buffer.getContents();

            expect(contents).toBeTruthy();

            if (contents !== false) {
                assert(ciphertext.equals(contents), 'encrypted plaintext should be equal to ciphertext');
            }
        });

        transform.write(plaintext.slice(0, 15));
        transform.write(plaintext.slice(15, 23));
        transform.end(plaintext.slice(23));
    });

    it('should decrypt', () => {
        const wake = new algorithm.Wake();
        wake.setKey(key);

        const transform = createDecryptStream(wake);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
        
        buffer.on('finish', () => {
            const contents = buffer.getContents();

            expect(contents).toBeTruthy();

            if (contents !== false) {
                assert(plaintext.equals(contents), 'decrypted ciphertext should be equal to plaintext');
            }
        });

        transform.write(ciphertext.slice(0, 17));
        transform.write(ciphertext.slice(17, 22));
        transform.end(ciphertext.slice(22));
    });


});

