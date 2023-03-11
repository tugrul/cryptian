


import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael128 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('rijndael-128 transform cbc mode', () => {


    const key = Buffer.alloc(16, 0); 
    key[0] = 1;

    const plaintext = Buffer.from(
        '1ac139626f36bd92dead6e521aa0370ec5b6db29105201e14f' +
        'c175ab319b4350402b34e1f83d9919145053c8124bb439189f', 'hex');

    const iv = Buffer.from('b5e21c207f89d64b6fe3b16572832f7f', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'b785b3c8de7052cbdc1662ff8dfd7866b91862ce4bf603552f52b7f3c6c6bb98' +
                        '78e63b461e98fa3d6704d6ac8d61fab24efd995cee8757d8c00bc5d39c8c7f83',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'b785b3c8de7052cbdc1662ff8dfd7866b91862ce4bf603552f52b7f3c6c6bb98' +
                        '78e63b461e98fa3d6704d6ac8d61fab2679ef9fad1832b1b886f345d3637f4e5',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'b785b3c8de7052cbdc1662ff8dfd7866b91862ce4bf603552f52b7f3c6c6bb98' +
                        '78e63b461e98fa3d6704d6ac8d61fab27d4565e0edaa1504345c1891f528ad7f',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'b785b3c8de7052cbdc1662ff8dfd7866b91862ce4bf603552f52b7f3c6c6bb98' +
                        '78e63b461e98fa3d6704d6ac8d61fab20cd19847860363606de59dc7a396913c',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'b785b3c8de7052cbdc1662ff8dfd7866b91862ce4bf603552f52b7f3c6c6bb98' +
                        '78e63b461e98fa3d6704d6ac8d61fab2b32c5409ad9a740a5cb91bf27a8be903',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'b785b3c8de7052cbdc1662ff8dfd7866b91862ce4bf603552f52b7f3c6c6bb98' +
                        '78e63b461e98fa3d6704d6ac8d61fab26e23a4d8a3f28ca6ab5efab9570285ae',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const rijndael = new algorithm.Rijndael128();
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

                const rijndael = new algorithm.Rijndael128();
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
            
            const rijndael = new algorithm.Rijndael128();
            rijndael.setKey(key);

            const cipher = new mode.cbc.Cipher(rijndael, iv);

            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael128();
            rijndael.setKey(key);

            const decipher = new mode.cbc.Decipher(rijndael, iv);

            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });
    

});

