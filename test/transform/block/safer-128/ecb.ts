


import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';


(typeof algorithm.Safer === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip) ('safer-128 transform ecb mode', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'aae6968a24fc0b376990e3ca826e39fe242e9641176daffd5b' +
        '65bbb552989a884ee69719335b3de1a54cc05136f433cc1d6a', 'hex');

    const iv = Buffer.from('27e4f1d57a36c8f4', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc99174e4d37b720e42a5',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc991d9f50f5689bfd5ea',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc991aaf4ebaafd1ffe18',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc99185d1339b009c83f6',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc991562698e71f124e72',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc9911feaf625930a62ae',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '1196e2cd14e1e192da1c2c0ae18ec8430ad0628c42fa1ee833a5aa43' +
                        '7aaaf8a507001da2331d9d34fa5678dfdbbcc9911feaf625930a62ae',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const safer = new algorithm.Safer();
                safer.setKey(key);

                const cipher = new mode.ecb.Cipher(safer, iv);

                const transform = createEncryptStream(cipher, target.padding);
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
                
                const decipher = new mode.ecb.Decipher(safer, iv);

                const transform = createDecryptStream(decipher, target.padding);
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
    

});

