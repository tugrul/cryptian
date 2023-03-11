
import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rc2 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('RC2 transform cbc mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'da5e812d4713d8ccf435a1ae49126c2a8d760ac3f3798497c9' +
        '2344536d0b811aaf1b09a4c53cc10a53011f8dfe7593732381', 'hex');

    const iv = Buffer.from('7419d854df1717b0', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbe400841ff5b24b7e5',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbe8fbd72fe9b917916',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbe662bb993d9b5d131',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbe2c53d2570d480ecb',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbea72e6bbffe74cfb3',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbed3d849e259990159',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '59c2233deb938167ba5d638ba62cb051a32eb32c2072b8d84baba184' +
                        '4a42b890b7d099bf56fddf34c53706e0e659ebbed3d849e259990159',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const rc2 = new algorithm.Rc2();
                rc2.setKey(key);

                const cipher = new mode.cbc.Cipher(rc2, iv);

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

                const rc2 = new algorithm.Rc2();
                rc2.setKey(key);
                
                const decipher = new mode.cbc.Decipher(rc2, iv);

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

