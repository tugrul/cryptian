
import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Rc2 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip) ('RC2 transform ecb mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '6a73f8121b1ca36439241bf2b9fba2e3613cb531ab5d7093a5' +
        '0939b899e35a3f51d217cccd21e7002b7cf0c156d3d7a88e6d', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63ede2bea19017467b48',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63edf981f2bf6cab21d3',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63ed25fe8a10d709019d',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63ed2a4a94ac73ce481f',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63edd1ab8eed9fc566ef',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63ed2a6e3e38ed222183',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '5a6b7165a8f826955e56b7460df2b7082d353256fb45d853b3368f91' +
                        '022ce016e3983642b81d78af2c24c6c9711c63ed2a6e3e38ed222183',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it) ('should encrypt', () => {
            
                const rc2 = new algorithm.Rc2();
                rc2.setKey(key);

                const cipher = new mode.ecb.Cipher(rc2, iv);

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

                const rc2 = new algorithm.Rc2();
                rc2.setKey(key);
                
                const decipher = new mode.ecb.Decipher(rc2, iv);

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

