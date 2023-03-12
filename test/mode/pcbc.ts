

import {expect} from '@jest/globals';

import { randomBytes } from 'crypto';
import assert from 'assert';
import cryptian from '../..';

const {algorithm: {Dummy}, mode: {pcbc}} = cryptian;


(typeof pcbc === 'object' ? describe : describe.skip) ('pcbc', () => {

    const plaintext  = Buffer.from('0a4e0adf528e898594699188930c6247493f3c17fce03723e123517d62533c4a', 'hex');
    const ciphertext = Buffer.from('09c31ca738fad69e97e487f0f9783d5c4ab22a6f96946838e2ae470508276351', 'hex');

    const iv = Buffer.from('038d16786a745f1b', 'hex');
    const dummy = new Dummy();


    describe('cipher', () => {

        it('undivided', () => {
            const cipher = new pcbc.Cipher(dummy, iv);

            assert(ciphertext.equals(cipher.transform(plaintext)), 'transformed plaintext should be equal to ciphertext');
        });

        it('divided', () => {
            const cipher = new pcbc.Cipher(dummy, iv);
            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 8)),
                cipher.transform(plaintext.slice(8))
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });
        
        describe('throw padding exception', () => {
            
            it('getBlockSize', () => {
                const cipher = new pcbc.Cipher(dummy, iv);
                assert.equal(cipher.getBlockSize(), dummy.getBlockSize(), 'cipher.getBlockSize() should equal algorithm.getBlockSize()');
            });
            
            it('transform using 5 bytes', () => {
                const cipher = new pcbc.Cipher(dummy, iv);

                expect(() => cipher.transform(randomBytes(5)))
                    .toThrowError('Data size should be aligned to algorithm block size.');

            });
            
            it('transform using 12 bytes', () => {

                const cipher = new pcbc.Cipher(dummy, iv);

                expect(() => cipher.transform(randomBytes(12)))
                    .toThrowError('Data size should be aligned to algorithm block size.');

            });
            
        });

    });

    
    describe('decipher', () => {


        it('undivided', () => {
            const decipher = new pcbc.Decipher(dummy, iv);

            assert(plaintext.equals(decipher.transform(ciphertext)), 'transformed ciphertext should be equal to plaintext');
        });


        it('divided', () => {
            const decipher = new pcbc.Decipher(dummy, iv);
            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 8)),
                decipher.transform(ciphertext.slice(8))
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });

        
        describe('throw padding exception', () => {
        
            it('getBlockSize', () => {
                const decipher = new pcbc.Decipher(dummy, iv);
                assert.equal(decipher.getBlockSize(), dummy.getBlockSize(), 'decipher.getBlockSize() should equal algorithm.getBlockSize()');
            });


            it('transform using 5 bytes', () => {
                const decipher = new pcbc.Decipher(dummy, iv);

                expect(() => decipher.transform(randomBytes(5))).toThrowError('Data size should be aligned to algorithm block size.');

            });


            it('transform using 12 bytes', () => {
                const decipher = new pcbc.Decipher(dummy, iv);

                expect(() => decipher.transform(randomBytes(12))).toThrowError('Data size should be aligned to algorithm block size.');
            });

        });
        
    });

});