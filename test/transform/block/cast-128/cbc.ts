

import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Cast128 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip) ('cast-128 transform cbc mode', () => {


    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '33ad490f54ae6fb2403ad8a9694fa6412caf2ea1eaa3d49eb6' +
        '7737974868c11d746fa7cc9ea34d7d9bdfb5d0cedcedcec27c', 'hex');

    const iv = Buffer.from('f1a3609bf97de038', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f859cae8643e44768f0e',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f8595b4ed7ba2dc500e1',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f8596a01c8cd3ceef712',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f85956ac1517dd484ebc',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f8591266c4083e91a92f',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f8590eb7efb0e583084c',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '44f9559454983d5e7fbe1d0386fd131d4402b0c3822a39389231ad2f' +
                        '42cc82ad210155a91ae03a14ce62210c0483f8590eb7efb0e583084c',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const cast128 = new algorithm.Cast128();
                cast128.setKey(key);

                const cipher = new mode.cbc.Cipher(cast128, iv);

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

                const cast128 = new algorithm.Cast128();
                cast128.setKey(key);
                
                const decipher = new mode.cbc.Decipher(cast128, iv);

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

