
import {expect} from '@jest/globals';

import { default as cryptian, 
    createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Safer === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip) ('safer-64 transform ofb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '3d02c24ebffb903e46feb964a244ba089cb5250eb1bfbc507d' +
        'af7170f659a57373cbed733f5493a4ec6424eb0e88dfaa47db', 'hex');

    const iv = Buffer.from('100214ab7ea4789a', 'hex');


    const ciphertext = Buffer.from(
        '16d12ea8255582f3dd915a6ba9acf86c228ddd53e126c8e14e' +
        '1dbbc7d1f6cc2126a3bee2d746238d528cdbb86c19162fd87c', 'hex');

    it('should encrypt', () => {
    
        const safer = new algorithm.Safer();
        safer.setKey(key);

        const cipher = new mode.ofb.Cipher(safer, iv);

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

        const decipher = new mode.ofb.Decipher(safer, iv);

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

