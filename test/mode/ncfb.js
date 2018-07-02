
const {algorithm, mode} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('ncfb', () => {

    it('should have namespace', () => {
        assert(typeof mode.ncfb === 'object', 'there is no namespace');
    });

    it('should be constructor', () => {
        assert(typeof mode.ncfb.Cipher === 'function', 'there is no Cipher constructor');
        assert(typeof mode.ncfb.Decipher === 'function', 'there is no Decipher constructor');
    });


    const plaintext  = new Buffer('88cc3d134aee5660f7623cf475fe9df20f773180bd70b0ef2aae00910ba087a1', 'hex');
    const ciphertext = new Buffer('ace98b99e6803c445b8bb76d937ea1b654fc86ed2e0e11597e52867c25ae96f8', 'hex');

    const iv = new Buffer('2425b68aac6e6a24', 'hex');
    const dummy = new algorithm.Dummy();


    it('should do cipher and decipher operations', () => {

        describe('cipher undivided', () => {
            const cipher = new mode.ncfb.Cipher(dummy, iv);

            assert(ciphertext.equals(cipher.transform(plaintext)), 'transformed plaintext should be equal to ciphertext');
        });

        describe('decipher undivided', () => {
            const decipher = new mode.ncfb.Decipher(dummy, iv);

            assert(plaintext.equals(decipher.transform(ciphertext)), 'transformed ciphertext should be equal to plaintext');
        });


        describe('cipher size 5', () => {
            const cipher = new mode.ncfb.Cipher(dummy, iv);

            assert(ciphertext.slice(0, 5).equals(cipher.transform(plaintext.slice(0, 5))), 'transformed plaintext should be equal to ciphertext');
        });


        describe('decipher size 5', () => {
            const decipher = new mode.ncfb.Decipher(dummy, iv);

            assert(plaintext.slice(0, 5).equals(decipher.transform(ciphertext.slice(0, 5))), 'transformed plaintext should be equal to ciphertext');
        });


        describe('cipher size 13', () => {
            const cipher = new mode.ncfb.Cipher(dummy, iv);

            assert(ciphertext.slice(0, 13).equals(cipher.transform(plaintext.slice(0, 13))), 'transformed plaintext should be equal to ciphertext');
        });


        describe('decipher size 13', () => {
            const decipher = new mode.ncfb.Decipher(dummy, iv);

            assert(plaintext.slice(0, 13).equals(decipher.transform(ciphertext.slice(0, 13))), 'transformed plaintext should be equal to ciphertext');
        });

        describe('cipher divided 5', () => {
            const cipher = new mode.ncfb.Cipher(dummy, iv);
            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 5)),
                cipher.transform(plaintext.slice(5))
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });

        describe('decipher divided 5', () => {
            const decipher = new mode.ncfb.Decipher(dummy, iv);
            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 5)),
                decipher.transform(ciphertext.slice(5))
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });

        describe('cipher divided 13', () => {
            const cipher = new mode.ncfb.Cipher(dummy, iv);
            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 13)),
                cipher.transform(plaintext.slice(13, 26)),
                cipher.transform(plaintext.slice(26)),
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });

        describe('decipher divided 13', () => {
            const decipher = new mode.ncfb.Decipher(dummy, iv);
            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 13)),
                decipher.transform(ciphertext.slice(13, 26)),
                decipher.transform(ciphertext.slice(26)),
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });


    });


});