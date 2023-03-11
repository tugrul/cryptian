

import {expect} from '@jest/globals';

import assert from 'assert';
import {default as cryptian, 
    padding, createEncryptStream, createDecryptStream, ModeList} from '../..';

const {algorithm, mode} = cryptian;

import { randomBytes, createDecipheriv, createCipheriv, getCiphers } from 'crypto';
    

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rijndael128 === 'function' ? describe : describe.skip) ('rijndael-128 with openssl aes-128 compat', () => {

    const modes: Array<{name: ModeList, openssl: string, skipIv?: boolean}> = [
        { name: ModeList.Cbc, openssl: 'aes-128-cbc' },
        { name: ModeList.Ecb, openssl: 'aes-128-ecb', skipIv: true },
        { name: ModeList.Cfb, openssl: 'aes-128-cfb8' },
        { name: ModeList.Ncfb, openssl: 'aes-128-cfb' },
        { name: ModeList.Ctr, openssl: 'aes-128-ctr' },
        { name: ModeList.Ofb, openssl: 'aes-128-ofb' }
    ];

    // list of available ciphers
    const ciphers = getCiphers();

    modes.forEach(({name, openssl, skipIv}) => {
        
    const targetMode = mode[name];

        (typeof targetMode === 'object' && ciphers.includes(name) ? describe : describe.skip) (name + ' mode pkcs7 padding', () => {
            
            it('encrypt cryptian to decrypt openssl', () => {
                
                const iv  = skipIv ? Buffer.alloc(0) : randomBytes(16);
                const key = randomBytes(16);
                const plaintext = randomBytes(50);
                
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                const cipher = new targetMode.Cipher(rijndael, iv);

                const encryptTransform = createEncryptStream(cipher, padding.Pkcs7);
                const decryptTransform = encryptTransform.pipe(createDecipheriv(openssl, key, iv));
                const buffer           = decryptTransform.pipe(new streamBuffers.WritableStreamBuffer());
                
                buffer.on('finish', () => {

                    const contents = buffer.getContents();

                    expect(contents).toBeTruthy();

                    if (contents !== false) {
                        assert(plaintext.equals(contents), 'encrypted plaintext should be equal to ciphertext');
                    }

                });
                
                encryptTransform.write(plaintext.slice(0, 22));
                encryptTransform.write(plaintext.slice(22, 39));
                encryptTransform.end(plaintext.slice(39));
                
            });

            
            it('encrypt openssl to decrypt cryptian', () => {
                
                const iv  = skipIv ? Buffer.alloc(0) : randomBytes(16);
                const key = randomBytes(16);
                const plaintext = randomBytes(50);
                
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                const decipher = new targetMode.Decipher(rijndael, iv);

                const encryptTransform = createCipheriv(openssl, key, iv);
                const decryptTransform = encryptTransform.pipe(createDecryptStream(decipher, padding.Pkcs7));
                const buffer           = decryptTransform.pipe(new streamBuffers.WritableStreamBuffer());
                
                buffer.on('finish', () => {
                    const contents = buffer.getContents();

                    expect(contents).toBeTruthy();

                    if (contents !== false) {
                        assert(plaintext.equals(contents), 'encrypted plaintext should be equal to ciphertext');
                    }
                });
                
                encryptTransform.write(plaintext.slice(0, 22));
                encryptTransform.write(plaintext.slice(22, 39));
                encryptTransform.end(plaintext.slice(39));
                
            });
            
        });

    });
    

});

