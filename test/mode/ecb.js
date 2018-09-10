
const {algorithm, mode} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('ecb', () => {

    it('should have namespace', () => {
        assert(typeof mode.ecb === 'object', 'there is no namespace');
    });

    it('should be constructor', () => {
        assert(typeof mode.ecb.Cipher === 'function', 'there is no Cipher constructor');
        assert(typeof mode.ecb.Decipher === 'function', 'there is no Decipher constructor');
    });

    const plaintext   = new Buffer('88cc3d134aee5660f7623cf475fe9df20f773180bd70b0ef2aae00910ba087a1', 'hex');
    const ciphertext  = new Buffer('88cc3d134aee5660f7623cf475fe9df20f773180bd70b0ef2aae00910ba087a1', 'hex');

    const iv = new Buffer('2425b68aac6e6a24', 'hex');
    const dummy = new algorithm.Dummy();

    it('should throw padding exception', () => {

        describe('cipher getBlockSize', () => {
            const cipher = new mode.ecb.Cipher(dummy, iv);
            assert.equal(cipher.getBlockSize(), dummy.getBlockSize(), 'cipher.getBlockSize() should equal algorithm.getBlockSize()');
        });
    
        describe('decipher getBlockSize', () => {
            const decipher = new mode.ecb.Decipher(dummy, iv);
            assert.equal(decipher.getBlockSize(), dummy.getBlockSize(), 'decipher.getBlockSize() should equal algorithm.getBlockSize()');
        });
    
        describe('cipher transform using 5 bytes', () => {
            const cipher = new mode.ecb.Cipher(dummy, iv);

            assert.throws(() => {
                cipher.transform(crypto.randomBytes(5));
            }, Error, 'Data size should be aligned to algorithm block size.');

        });

        describe('decipher transform using 5 bytes', () => {
            const decipher = new mode.ecb.Decipher(dummy, iv);

            assert.throws(() => {
                decipher.transform(crypto.randomBytes(5));
            }, Error, 'Data size should be aligned to algorithm block size.');
        });


        describe('cipher transform using 12 bytes', () => {
            const cipher = new mode.ecb.Cipher(dummy, iv);

            assert.throws(() => {
                cipher.transform(crypto.randomBytes(12));
            }, Error, 'Data size should be aligned to algorithm block size.');

        });

        describe('decipher transform using 12 bytes', () => {
            const decipher = new mode.ecb.Decipher(dummy, iv);

            assert.throws(() => {
                decipher.transform(crypto.randomBytes(12));
            }, Error, 'Data size should be aligned to algorithm block size.');
        });

    });

    it('should do cipher and decipher operations', () => {

        describe('cipher undivided', () => {
            const cipher = new mode.ecb.Cipher(dummy, iv);

            assert(ciphertext.equals(cipher.transform(plaintext)), 'transformed plaintext should be equal to ciphertext');
        });

        describe('decipher undivided', () => {
            const decipher = new mode.ecb.Decipher(dummy, iv);

            assert(plaintext.equals(decipher.transform(ciphertext)), 'transformed ciphertext should be equal to plaintext');
        });

        describe('cipher divided', () => {
            const cipher = new mode.ecb.Cipher(dummy, iv);
            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 8)),
                cipher.transform(plaintext.slice(8))
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });

        describe('decipher divided', () => {
            const decipher = new mode.ecb.Decipher(dummy, iv);
            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 8)),
                decipher.transform(ciphertext.slice(8))
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });


    });


});