

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Safer === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('safer-64 transform cbc mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'd1eb2c76df4dea1104e0eeed2b084e9b97c6201c15f543c967' +
        'f684bd0f10cb755315cc9a1f04b0931aa0f526755512b1356a', 'hex');

    const iv = Buffer.from('796ad380b9819164', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7db152ec36f98fdce1f',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7db1998248d54857209',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7dbfdd55904092ae45a',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7dbbbbe4b1a7cb8f86f',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7db45d0e548c4eb68c7',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7db8fbf702cfa6ac19d',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '70e371c4ce10ef884ebc5a466d51a4734781380c969001377cd2d322' +
                        '53b9dcb8cb3b85f6ccac3707c016b044a06ae7db8fbf702cfa6ac19d',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const safer = new algorithm.Safer();
                safer.setKey(key);

                const cipher = new mode.cbc.Cipher(safer, iv);

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
                
                const decipher = new mode.cbc.Decipher(safer, iv);

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

