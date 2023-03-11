

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Loki97 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('loki97 transform cbc mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '69b47bd85293a6968f1802d7aa4794ad453f2e17ad27110a53' +
        '4684df3cd748a279a51a384dabb6d67e7003a5ed3adfaeea90', 'hex');

    const iv = Buffer.from('78c7c2a31cb9197622d246c58918e7dc', 'hex');



    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'fa1ce71c28f56422a8eb072fab717b7d940c56a8410784831e7042383d26cb7c' +
                        '7d336874f16e4188d916f41f3a17896a97badd82768b4faea8ac23e896543557',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'fa1ce71c28f56422a8eb072fab717b7d940c56a8410784831e7042383d26cb7c' +
                        '7d336874f16e4188d916f41f3a17896ae7823c0a99c641643b2e0cab72f0e58c',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'fa1ce71c28f56422a8eb072fab717b7d940c56a8410784831e7042383d26cb7c' +
                        '7d336874f16e4188d916f41f3a17896af252b74221a2ea47d699c411faf00982',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'fa1ce71c28f56422a8eb072fab717b7d940c56a8410784831e7042383d26cb7c' +
                        '7d336874f16e4188d916f41f3a17896a33576cb916d23fbed3cabfa797bf7a10',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'fa1ce71c28f56422a8eb072fab717b7d940c56a8410784831e7042383d26cb7c' +
                        '7d336874f16e4188d916f41f3a17896a94e34fb629b847f3ee529ff512b808e8',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'fa1ce71c28f56422a8eb072fab717b7d940c56a8410784831e7042383d26cb7c' +
                        '7d336874f16e4188d916f41f3a17896a48028dde8f2c7716ba1fabd93a0d5476',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const loki97 = new algorithm.Loki97();
                loki97.setKey(key);

                const cipher = new mode.cbc.Cipher(loki97, iv);

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

                const loki97 = new algorithm.Loki97();
                loki97.setKey(key);
                
                const decipher = new mode.cbc.Decipher(loki97, iv);

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
            
            const loki97 = new algorithm.Loki97();
            loki97.setKey(key);

            const cipher = new mode.cbc.Cipher(loki97, iv);
            
            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const loki97 = new algorithm.Loki97();
            loki97.setKey(key);

            const decipher = new mode.cbc.Decipher(loki97, iv);
            
            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });


    

});

