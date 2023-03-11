

import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Xtea === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip) ('xtea transform cbc mode', () => {


    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'c3147c60d0c2b6434e1c0182e78437596e7e2744380a1ea20c' +
        '19a61e6f63d0fbe41e78d13980028c995d8fe3262ded68c139', 'hex');

    const iv = Buffer.from('25c35926b580dd0c', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f9aa9654771744593b',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f951923bd5a309fef9',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f9275852acbcc13112',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f97f276ad17bba1123',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f98c6500ca933c7c15',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f9681b823d30a5f9af',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'b3d1a8c5b6e9774bba330e3256d40f070f2cc3cd2e4f314a6d355b5a' +
                        '20c6fb415b99d4a03b584c2676ac60d4a95059f9681b823d30a5f9af',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const xtea = new algorithm.Xtea();
                xtea.setKey(key);

                const cipher = new mode.cbc.Cipher(xtea, iv);

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

                const xtea = new algorithm.Xtea();
                xtea.setKey(key);
                
                const decipher = new mode.cbc.Decipher(xtea, iv);

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

