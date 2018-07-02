
const {algorithm} = require('../..');
const assert = require('assert');

describe('blowfish', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = new Buffer(56);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // plaintext from mcrypt test rule
    const plaintext  = new Buffer('0001020304050607', 'hex');

    describe('standard', () => {

        // ciphertext from mcrypt test rule
        const ciphertext = new Buffer('c8c033bc57874d74', 'hex');

        it('should do encrypt and decrypt operations', () => {

            describe('encrypt', () => {
                const blowfish = new algorithm.Blowfish();

                blowfish.setKey(key);

                assert(ciphertext.equals(blowfish.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
            });

            describe('decrypt', () => {
                const blowfish = new algorithm.Blowfish();

                blowfish.setKey(key);

                assert(plaintext.equals(blowfish.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
            });

        });

    });

    describe('endian compat', () => {

        // ciphertext from mcrypt test rule
        const ciphertext = new Buffer('de8e9a3a9cd44280', 'hex');


        it('should do encrypt and decrypt operations', () => {

            describe('encrypt', () => {
                const blowfish = new algorithm.Blowfish();

                blowfish.setKey(key);

                blowfish.setEndianCompat(true);

                assert(ciphertext.equals(blowfish.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
            });

            describe('decrypt', () => {
                const blowfish = new algorithm.Blowfish();

                blowfish.setKey(key);

                blowfish.setEndianCompat(true);

                assert(plaintext.equals(blowfish.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
            });

        });

    });



});

