

import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Xtea === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip) ('xtea transform ecb mode', () => {


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
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a48870fc83fbbb1957',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a4f93b6e5941813996',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a41b5247c035844799',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a46abe2bc81c3e8cca',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a4565034114459e0fb',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a409f672b60207064e',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'f637f8dd4eb8c8bf5fac0572ecd73ff5a477180cd46270f5f05308af' +
                        '1aa8f7318c9dcd27c66e0603d66cda97f371c2a409f672b60207064e',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const xtea = new algorithm.Xtea();
                xtea.setKey(key);

                const cipher = new mode.ecb.Cipher(xtea, iv);

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
                
                const decipher = new mode.ecb.Decipher(xtea, iv);

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

