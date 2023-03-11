

import {expect, jest, test} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Threeway === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('threeway transform cbc mode', () => {


    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '4d737dcf235e846eb77675f3a7972c771f93f9a07f7460d92c' +
        '4f7f0230b547b3ee4fd6041fff836444231b717df75f079825', 'hex');

    const iv = Buffer.from('cc2ca7c51576f075fc9bad8b', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'fd3101102541ee1e5c734c583a3e882bf03af02e4d27bb06c1f21fb65c83' +
                        'd904bcf479227f7d60c04de58be87e99895b9d0014911a15cb32753b0613',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'fd3101102541ee1e5c734c583a3e882bf03af02e4d27bb06c1f21fb65c83' +
                        'd904bcf479227f7d60c04de58be87e99895ba09996465fb8587e5a0b04d0',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'fd3101102541ee1e5c734c583a3e882bf03af02e4d27bb06c1f21fb65c83' +
                        'd904bcf479227f7d60c04de58be87e99895bd4bd81c6a8aa8a499fc171c0',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'fd3101102541ee1e5c734c583a3e882bf03af02e4d27bb06c1f21fb65c83' +
                        'd904bcf479227f7d60c04de58be87e99895b91761f2d6cfcdd03db8e79cd',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'fd3101102541ee1e5c734c583a3e882bf03af02e4d27bb06c1f21fb65c83' +
                        'd904bcf479227f7d60c04de58be87e99895be49f0e5502e71918ec82bdea',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'fd3101102541ee1e5c734c583a3e882bf03af02e4d27bb06c1f21fb65c83' +
                        'd904bcf479227f7d60c04de58be87e99895b98c4cafd960470db798dde02',
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

                const cipher = new mode.cbc.Cipher(threeway, iv);

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
                
                const decipher = new mode.cbc.Decipher(threeway, iv);

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

            const cipher = new mode.cbc.Cipher(threeway, iv);
            
            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const threeway = new algorithm.Threeway();
            threeway.setKey(key);

            const decipher = new mode.cbc.Decipher(threeway, iv);
            
            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });

    

});

