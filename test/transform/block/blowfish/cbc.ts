

import {expect} from '@jest/globals';

import { default as cryptian, 
    padding, createEncryptStream, createDecryptStream } from "../../../..";

const {algorithm, mode} = cryptian;

import assert from 'assert';

import streamBuffers from 'stream-buffers';

(typeof algorithm.Blowfish === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip) ('blowfish transform cbc mode', () => {

    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'd7944f4102aced25534ed06b413cc5763fc53199fd6ff2fcc2' +
        '5d7d7c476d0257aca394c1693645f85f84ce8a238fb3955372', 'hex');

    const iv = Buffer.from('e3343cad08296fdc', 'hex');

    describe('standard', () => {

        const fixture = [
            {
                title: 'null padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981bfe75f97bfb50f6a6',
                padding: padding.Null
            },
            {
                title: 'space padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981b843c91843b1ccd78',
                padding: padding.Space
            },
            {
                title: 'ansi-x923 padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981b6e7011f7da6993e7',
                padding: padding.AnsiX923
            },
            {
                title: 'iso-10126 padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981b2dbce6ffdc88a3ff',
                padding: padding.Iso10126,
                skipEncrypt: true // because there are random bytes in padding and not match
            },
            {
                title: 'iso-7816 padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981b26823608487f6570',
                padding: padding.Iso7816
            },
            {
                title: 'PKCS5 padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981b242cf115f4258982',
                padding: padding.Pkcs5
            },
            {
                title: 'PKCS7 padding',
                ciphertext: '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                            'd7b75f21e1f5963d0eb649dd32f29e0e1e21981b242cf115f4258982',
                padding: padding.Pkcs7
            }
        ];
    
        fixture.forEach(target => {

            describe(target.title, () => {
    
                const ciphertext = Buffer.from(target.ciphertext, 'hex');


                (target.skipEncrypt ? xit : it) ('should encrypt', () => {
                
                    const blowfish = new algorithm.Blowfish();
                    blowfish.setKey(key);

                    const cipher = new mode.cbc.Cipher(blowfish, iv);

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

                    const blowfish = new algorithm.Blowfish();
                    blowfish.setKey(key);
                    
                    const decipher = new mode.cbc.Decipher(blowfish, iv);

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

    describe('endian compat', () => {

        const fixture = [
            {
                title: 'null padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a497d5e67c0b16cd79c',
                padding: padding.Null
            },
            {
                title: 'space padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a4921abe1ac9a150f82',
                padding: padding.Space
            },
            {
                title: 'ansi-x923 padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a497127a9424cda3966',
                padding: padding.AnsiX923
            },
            {
                title: 'iso-10126 padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a4915ba9f8fe3597c40',
                padding: padding.Iso10126,
                skipEncrypt: true // because there are random bytes in padding and not match
            },
            {
                title: 'iso-7816 padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a499bc059429102d631',
                padding: padding.Iso7816
            },
            {
                title: 'PKCS5 padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a493ec89ae20d96aa44',
                padding: padding.Pkcs5
            },
            {
                title: 'PKCS7 padding',
                ciphertext: '0c7149f6ac781f51c6822d8b166c83530664cdb709b29017d7293dc7' +
                            '02ff763b6868cedc16095bab971ad332a96c9a493ec89ae20d96aa44',
                padding: padding.Pkcs7
            }
        ];
    
        fixture.forEach(target => {

        
            describe(target.title, () => {
    
                const ciphertext = Buffer.from(target.ciphertext, 'hex');

                it('should encrypt', () => {
                
                    if (target.skipEncrypt) {
                        return;
                    }
                
                    const blowfish = new algorithm.Blowfish();
                    blowfish.setKey(key);
                    blowfish.setEndianCompat(true);

                    const cipher = new mode.cbc.Cipher(blowfish, iv);

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

                    const blowfish = new algorithm.Blowfish();
                    blowfish.setKey(key);
                    blowfish.setEndianCompat(true);
                    
                    const decipher = new mode.cbc.Decipher(blowfish, iv);

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
    

});

