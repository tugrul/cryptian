

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Threeway === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('threeway transform ecb mode', () => {


    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'e47d2af48f3cd2930e15b5447c1f8ec239387c510bf6e9e580' +
        '894b8091162d5301838afbd2d5e6e1a8200a5518672e531319', 'hex');

    const iv = Buffer.from('e70abf832a8950682d118dd1', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '81e564d74b648a5cda1f69a03aac5497d45df532181f07b766d3393e3300' +
                        '6adbac95a5e7fb5bc6e57d922021d09130864fbc8c4cf915c4676b61818c',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '81e564d74b648a5cda1f69a03aac5497d45df532181f07b766d3393e3300' +
                        '6adbac95a5e7fb5bc6e57d922021d091308623cb09a63a8d240794f729e6',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '81e564d74b648a5cda1f69a03aac5497d45df532181f07b766d3393e3300' +
                        '6adbac95a5e7fb5bc6e57d922021d091308610315347d26d386ef29798a5',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '81e564d74b648a5cda1f69a03aac5497d45df532181f07b766d3393e3300' +
                        '6adbac95a5e7fb5bc6e57d922021d09130860cc1f60cb7241e0af1f9319f',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '81e564d74b648a5cda1f69a03aac5497d45df532181f07b766d3393e3300' +
                        '6adbac95a5e7fb5bc6e57d922021d0913086449fc0e3cca17b4ce0113daf',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '81e564d74b648a5cda1f69a03aac5497d45df532181f07b766d3393e3300' +
                        '6adbac95a5e7fb5bc6e57d922021d091308659c042ec00b3737854ffae60',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const threeway = new algorithm.Threeway();
                threeway.setKey(key);

                const cipher = new mode.ecb.Cipher(threeway, iv);

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

                const threeway = new algorithm.Threeway();
                threeway.setKey(key);
                
                const decipher = new mode.ecb.Decipher(threeway, iv);

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
            
            const threeway = new algorithm.Threeway();
            threeway.setKey(key);

            const cipher = new mode.ecb.Cipher(threeway, iv);
            
            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const threeway = new algorithm.Threeway();
            threeway.setKey(key);

            const decipher = new mode.ecb.Decipher(threeway, iv);
            
            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });

    

});

