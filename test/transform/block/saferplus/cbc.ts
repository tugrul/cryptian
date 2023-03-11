
import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Saferplus === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip) ('saferplus transform cbc mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'cdee2066b1418a25c4ce4d916375a1be5c413abff78aafe16b' +
        '95dc7dfc101c7d09cfb57f243541ccb94b7fba72e7afad77f5', 'hex');

    const iv = Buffer.from('8455932f75a3f8d00d9a6a46f4925e1e', 'hex');



    const fixture = [
        {
            title: 'null padding',
            ciphertext: '5e818a02490b5e741c5f8376dfad1e42e3afb7fc0ed52fa6d3990144ee01954a' +
                        '127195fe6452e716e7425dbe768acf2274df8516862efe8e2fdc9e1ff0ffdd85',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '5e818a02490b5e741c5f8376dfad1e42e3afb7fc0ed52fa6d3990144ee01954a' +
                        '127195fe6452e716e7425dbe768acf22ae8ff25885d2da5e2883e529708a1810',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '5e818a02490b5e741c5f8376dfad1e42e3afb7fc0ed52fa6d3990144ee01954a' +
                        '127195fe6452e716e7425dbe768acf228753bedbe00559e9cf071be4fbef7402',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '5e818a02490b5e741c5f8376dfad1e42e3afb7fc0ed52fa6d3990144ee01954a' +
                        '127195fe6452e716e7425dbe768acf22548319138e04656c02298e2d22a3a84c',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '5e818a02490b5e741c5f8376dfad1e42e3afb7fc0ed52fa6d3990144ee01954a' +
                        '127195fe6452e716e7425dbe768acf2201deff5eacfce58a40931118f1fb7e0b',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '5e818a02490b5e741c5f8376dfad1e42e3afb7fc0ed52fa6d3990144ee01954a' +
                        '127195fe6452e716e7425dbe768acf22aa34490458e60be6b7691e3770edc4df',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const saferplus = new algorithm.Saferplus();
                saferplus.setKey(key);

                const cipher = new mode.cbc.Cipher(saferplus, iv);

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

                const saferplus = new algorithm.Saferplus();
                saferplus.setKey(key);
                
                const decipher = new mode.cbc.Decipher(saferplus, iv);

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
    
    describe('throw exception', () => {
        
        it('should create encrypt stream', () => {
            
            const saferplus = new algorithm.Saferplus();
            saferplus.setKey(key);

            const cipher = new mode.cbc.Cipher(saferplus, iv);
            
            assert.throws(() => {
                createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const saferplus = new algorithm.Saferplus();
            saferplus.setKey(key);

            const decipher = new mode.cbc.Decipher(saferplus, iv);
            
            assert.throws(() => {
                createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });

});

