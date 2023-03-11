

import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Loki97 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip) ('loki97 transform ecb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '2e1757eedd1101c6a4196d8b7e0cc87c39a3cacff54f103696' +
        'c33100af570433b6e41e2d6c47da3487d6e99e7c21b72ca6b7', 'hex');

    const iv = Buffer.alloc(0);



    const fixture = [
        {
            title: 'null padding',
            ciphertext: '232a7eed1e7cfbf0742f802c716caf784833a16aba89c1cdf8444da45882b30d' +
                        'e36a4217fe6e0337209ccce6af6a4ffc8dcbf02896fde46ce5c2eacae420e7ec',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '232a7eed1e7cfbf0742f802c716caf784833a16aba89c1cdf8444da45882b30d' +
                        'e36a4217fe6e0337209ccce6af6a4ffcb0e7bb3cb931128d67e7d56cfa84a624',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '232a7eed1e7cfbf0742f802c716caf784833a16aba89c1cdf8444da45882b30d' +
                        'e36a4217fe6e0337209ccce6af6a4ffc7301fd57501927601b1ae24a26941006',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '232a7eed1e7cfbf0742f802c716caf784833a16aba89c1cdf8444da45882b30d' +
                        'e36a4217fe6e0337209ccce6af6a4ffc69c361a8fdcf9610f03a888190c6fc90',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '232a7eed1e7cfbf0742f802c716caf784833a16aba89c1cdf8444da45882b30d' +
                        'e36a4217fe6e0337209ccce6af6a4ffcde211e23e78edf685b4189d59e33fdde',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '232a7eed1e7cfbf0742f802c716caf784833a16aba89c1cdf8444da45882b30d' +
                        'e36a4217fe6e0337209ccce6af6a4ffc59bc8de01b69e2a08b2bbf90e15239e4',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const loki97 = new algorithm.Loki97();
                loki97.setKey(key);

                const cipher = new mode.ecb.Cipher(loki97, iv);

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
                
                const decipher = new mode.ecb.Decipher(loki97, iv);

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

            const cipher = new mode.ecb.Cipher(loki97, iv);
            
            assert.throws(() => {
                createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const loki97 = new algorithm.Loki97();
            loki97.setKey(key);

            const decipher = new mode.ecb.Decipher(loki97, iv);
            
            assert.throws(() => {
                createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });
    

});

