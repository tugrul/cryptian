

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Tripledes === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('tripledes transform cbc mode', () => {


    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    const plaintext = Buffer.from(
        '40a3c967984260e6cd06f379335354f3967c16788e8ac09fdb' +
        'c8b26da9b518c3603a96a88e0fd2d459b9957855b5092132eb', 'hex');

    const iv = Buffer.from('63b4d0f1a8607d9a', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d62566ae5931444755db68',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d62566da9b73a44fbba1a3',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d6256687f8a784605c4559',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d62566d104b9e9b8a6d323',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d625666999e9de132444da',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d62566363e0f7ab25e33c5',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'c0380e65ef977f71552410b0f0700882927bdfe99f362489a3370798' +
                        'cf67b79332b573e1e7b850becc04969df2d62566363e0f7ab25e33c5',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const tripledes = new algorithm.Tripledes();
                tripledes.setKey(key);

                const cipher = new mode.cbc.Cipher(tripledes, iv);

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

                const tripledes = new algorithm.Tripledes();
                tripledes.setKey(key);
                
                const decipher = new mode.cbc.Decipher(tripledes, iv);

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

