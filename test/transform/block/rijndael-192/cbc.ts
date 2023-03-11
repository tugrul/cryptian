


import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael192 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip) ('rijndael-192 transform cbc mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '1520b678322c91ce177743c202088415299c844c26b8d469f1' +
        'a7d362c993254a364e1c0a3d67e26aa14de1685fe22c4c635d', 'hex');

    const iv = Buffer.from('5e9f68fb9a26237a25eeaade5b588a7d86904ffd7646a221', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'ed20bbf585b24e39ef24c8e8f4dd8af5060a10a1a13d240b8def7652e5712248bbe1d141' +
                        '0ebbf83056184e3ed908a4589cdda138c0c5ba811f1b835e2055290f3b2f670b250043ed',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'ed20bbf585b24e39ef24c8e8f4dd8af5060a10a1a13d240b8def7652e5712248bbe1d141' +
                        '0ebbf83056184e3ed908a458e836d64a5405d06386651c78290c28b502bc3639b8e5ee06',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'ed20bbf585b24e39ef24c8e8f4dd8af5060a10a1a13d240b8def7652e5712248bbe1d141' +
                        '0ebbf83056184e3ed908a458efb38d1acb81d961c12bdf4929c4764e70ff81499cfdc1b6',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'ed20bbf585b24e39ef24c8e8f4dd8af5060a10a1a13d240b8def7652e5712248bbe1d141' +
                        '0ebbf83056184e3ed908a4584dec35b2344296a52903add5f3215de49b7853c5f2962755',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'ed20bbf585b24e39ef24c8e8f4dd8af5060a10a1a13d240b8def7652e5712248bbe1d141' +
                        '0ebbf83056184e3ed908a458ba0c7e6f7d6ac001ef5be741de1eea86f5bb643e5fd763d6',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'ed20bbf585b24e39ef24c8e8f4dd8af5060a10a1a13d240b8def7652e5712248bbe1d141' +
                        '0ebbf83056184e3ed908a458a03e935f1dd9aa572f73e46693385015a07d131177008c05',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const rijndael = new algorithm.Rijndael192();
                rijndael.setKey(key);

                const cipher = new mode.cbc.Cipher(rijndael, iv);

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

                const rijndael = new algorithm.Rijndael192();
                rijndael.setKey(key);
                
                const decipher = new mode.cbc.Decipher(rijndael, iv);

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
    
    describe('PKCS5 throw exception', () => {
        
        it('should create encrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael192();
            rijndael.setKey(key);

            const cipher = new mode.cbc.Cipher(rijndael, iv);

            assert.throws(() => {
                createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael192();
            rijndael.setKey(key);

            const decipher = new mode.cbc.Decipher(rijndael, iv);

            assert.throws(() => {
                createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });
    

});

