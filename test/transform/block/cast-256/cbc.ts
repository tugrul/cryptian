

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Cast256 === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('cast-256 transform cbc mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '7cbf7c0d59fbe90839775a2ba3368705837a3c623d88c490fd' +
        '4e005506d9c0f9b2be82e0122857417fe9903a6dfd860b9dab', 'hex');

    const iv = Buffer.from('cbf7190d3d8409186d5498959a1aefd3', 'hex');



    const fixture = [
        {
            title: 'null padding',
            ciphertext: '4b3ee7b3ac6cd435dce6d53bf05e32f0cc4accf99e5a714d4b1b70386bdbca89' +
                        'f3380f23fa162db101e87b2ca234719071c62a7f7292beff805197e137866b7e',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '4b3ee7b3ac6cd435dce6d53bf05e32f0cc4accf99e5a714d4b1b70386bdbca89' +
                        'f3380f23fa162db101e87b2ca234719021f43e64475fbf19e18d8513b5c8b8f7',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '4b3ee7b3ac6cd435dce6d53bf05e32f0cc4accf99e5a714d4b1b70386bdbca89' +
                        'f3380f23fa162db101e87b2ca23471903360d3002f5cb8c2a2959f11e0c1aa6c',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '4b3ee7b3ac6cd435dce6d53bf05e32f0cc4accf99e5a714d4b1b70386bdbca89' +
                        'f3380f23fa162db101e87b2ca23471906d332a84e1243656a70578af130bd117',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '4b3ee7b3ac6cd435dce6d53bf05e32f0cc4accf99e5a714d4b1b70386bdbca89' +
                        'f3380f23fa162db101e87b2ca2347190789b7a94a7ca0461c86a1e3b9aa42991',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '4b3ee7b3ac6cd435dce6d53bf05e32f0cc4accf99e5a714d4b1b70386bdbca89' +
                        'f3380f23fa162db101e87b2ca234719010ce3d5fa661795b78c75339f28db449',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const cast256 = new algorithm.Cast256();
                cast256.setKey(key);

                const cipher = new mode.cbc.Cipher(cast256, iv);

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

                const cast256 = new algorithm.Cast256();
                cast256.setKey(key);
                
                const decipher = new mode.cbc.Decipher(cast256, iv);

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
            
            const cast256 = new algorithm.Cast256();
            cast256.setKey(key);

            const cipher = new mode.cbc.Cipher(cast256, iv);
            
            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const cast256 = new algorithm.Cast256();
            cast256.setKey(key);

            const decipher = new mode.cbc.Decipher(cast256, iv);
            
            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });


});

