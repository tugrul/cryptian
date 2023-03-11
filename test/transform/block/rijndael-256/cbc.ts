

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael256 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('rijndael-256 transform cbc mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '1d283355039717ee232d404f65a01fe331a05979a54d7af8be' +
        '81d4bb1cd103d3c18cf6439c48ff2b8325ce76eb278907782d', 'hex');

    const iv = Buffer.from('9a6e60af634cb8a199e84585e3d97bb7d088b538c3fceb84cec043daf80e0d90', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'a67e70fba5d1c323c1895f07f96fe2a145682e56fe4a3153185d57435b9fc8c0' +
                        '65ccbd7cf535031f1272d942db6e06362cad00a15d053fb1efc6b02dfe16f10e',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'a67e70fba5d1c323c1895f07f96fe2a145682e56fe4a3153185d57435b9fc8c0' +
                        '8ad8ad8827277697e319413fefe062a96cb1556198e28afb0d45b824240cb320',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'a67e70fba5d1c323c1895f07f96fe2a145682e56fe4a3153185d57435b9fc8c0' +
                        'e0313cb33a4bd85f59d07e7342978d1c60a44fe6e35f0217cf3a9c24f14c940e',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'a67e70fba5d1c323c1895f07f96fe2a145682e56fe4a3153185d57435b9fc8c0' +
                        '7ab241e8cb4fa91c42de46f87e45ac014f3e5f37ab2adb585da56f99e460fcc3',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'a67e70fba5d1c323c1895f07f96fe2a145682e56fe4a3153185d57435b9fc8c0' +
                        '0d301c9b5c6fc0d6c4430874567cf6bbf0a3957ffa897672c932d6d0f0b155be',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'a67e70fba5d1c323c1895f07f96fe2a145682e56fe4a3153185d57435b9fc8c0' +
                        'f3a7cd9e3c2c4e2d0cc479e4b80dbee5ec13ca44de8222d41b8e0498a7b35b0d',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const rijndael = new algorithm.Rijndael256();
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

                const rijndael = new algorithm.Rijndael256();
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
            
            const rijndael = new algorithm.Rijndael256();
            rijndael.setKey(key);

            const cipher = new mode.cbc.Cipher(rijndael, iv);

            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael256();
            rijndael.setKey(key);

            const decipher = new mode.cbc.Decipher(rijndael, iv);

            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });

    

});

