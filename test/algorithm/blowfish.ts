
const {algorithm} = require('../..');

import assert from 'assert';

import cryptian from '../..';

const {Blowfish} = cryptian.algorithm;

(typeof Blowfish === 'function'? describe : describe.skip)
('blowfish', () => {

    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // plaintext from mcrypt test rule
    const plaintext  = Buffer.from('0001020304050607', 'hex');

    describe('standard', () => {

        // ciphertext from mcrypt test rule
        const ciphertext = Buffer.from('c8c033bc57874d74', 'hex');

        it('should encrypt', () => {

            const blowfish = new Blowfish();

            blowfish.setKey(key);

            assert(ciphertext.equals(blowfish.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

        });
        
        it('should decrypt', () => {

            const blowfish = new Blowfish();

            blowfish.setKey(key);

            assert(plaintext.equals(blowfish.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

        });

    });

    describe('endian compat', () => {

        // ciphertext from mcrypt test rule
        const ciphertext = Buffer.from('de8e9a3a9cd44280', 'hex');


        it('should encrypt', () => {

            const blowfish = new Blowfish();

            blowfish.setKey(key);

            blowfish.setEndianCompat(true);

            assert(ciphertext.equals(blowfish.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

        });
        
        it('should decrypt', () => {

            const blowfish = new Blowfish();

            blowfish.setKey(key);

            blowfish.setEndianCompat(true);

            assert(plaintext.equals(blowfish.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

        });

    });



});

