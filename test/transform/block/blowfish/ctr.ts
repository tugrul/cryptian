
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Blowfish === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip) ('blowfish transform ctr mode', () => {


    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '5517d3d450db0be089159c6557e423575dd2c021671edc9c90' +
        '018a43772cd5ce3c1bc89e54a0c10b37745938f07bfd460f35', 'hex');

    const iv = Buffer.from('c144b13252edff4d', 'hex');

    describe('standard', () => {

        const ciphertext = Buffer.from(
            'e223e5cfbe22a26740b49d0e54afcdb8642222aad603b03cc7' +
            '7c1f5353a21455c24d9e7844825e2ef45bc6a5872ac389696f', 'hex');

        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);

            const cipher = new mode.ctr.Cipher(blowfish, iv);

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

            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            
            const decipher = new mode.ctr.Decipher(blowfish, iv);

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

    describe('endian compat', () => {
        
        const ciphertext = Buffer.from(
            '1ddb38c8cbba70ce8016d2f6603cf30c2bf68be155955616ed' +
            '03b8eb7477dfbe5c32a09541556dd661556d8509ce764127af', 'hex');

            
        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const cipher = new mode.ctr.Cipher(blowfish, iv);

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

            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const decipher = new mode.ctr.Decipher(blowfish, iv);

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
    

});

