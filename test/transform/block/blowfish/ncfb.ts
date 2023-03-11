
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Blowfish === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('blowfish transform ncfb mode', () => {

    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'f321a0b6bdd0f6400a04800871ed0cdb6180c9d91267aaadc3' +
        'e1237dfbfe013cb2a2edbaddf8e59bb67635018e635f41573a', 'hex');

    const iv = Buffer.from('999b2160c293ee2e', 'hex');

    describe('standard', () => {

        const ciphertext = Buffer.from(
            '8699a5c96966171fbec38424817c6c4687b70cc72fc32d1e10' +
            '7c9047c65d159500df01e4d29b529d6fc5bae51e7aa6cbb948', 'hex');


        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);

            const cipher = new mode.ncfb.Cipher(blowfish, iv);

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
            
            const decipher = new mode.ncfb.Decipher(blowfish, iv);

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
            '3b7216c348c74970614f2b1e1e06ef81d806a4a09d07be8add' +
            '40dd18f55a0566ed91fa584d4cea315b6f3184d2e9f3f7925e', 'hex');


        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const cipher = new mode.ncfb.Cipher(blowfish, iv);

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
            
            const decipher = new mode.ncfb.Decipher(blowfish, iv);

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

