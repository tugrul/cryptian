

import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Cast128 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip) ('cast-128 transform ecb mode', () => {


    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '4f4037c503026d0d20b3c4a61650b45b1b7ab43966dd4c52a7' +
        'e5658cf402002a02539664544516e5d7ce9a3c898079516de9', 'hex');

    const iv = Buffer.alloc(0);

    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b7239029f8f75b98fb4e98',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b723907483b9c506cc580c',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b72390d93db526d36d24c6',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b72390b8ff398b382e9f4b',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b72390ea3394c81da159ac',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b7239034318a01f273ae6d',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'a59e62ba51020b09b5d179ed6ba9c291008d59f19775f49f37ff241d' +
                        'aa236e70dbf79f104e8d9a6544d1705b00b7239034318a01f273ae6d',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const cast128 = new algorithm.Cast128();
                cast128.setKey(key);

                const cipher = new mode.ecb.Cipher(cast128, iv);

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

                const cast128 = new algorithm.Cast128();
                cast128.setKey(key);
                
                const decipher = new mode.ecb.Decipher(cast128, iv);

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



});

