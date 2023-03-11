

import assert from "assert";

import cryptian from '../..';

const {Cast128} = cryptian.algorithm;

(typeof Cast128 === 'function'? describe : describe.skip) ('cast-128', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('434e25460c8c9525', 'hex');

    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const cast128 = new Cast128();

        cast128.setKey(key);

        assert(ciphertext.equals(cast128.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    it('should decrypt', () => {

        const cast128 = new Cast128();
        
        cast128.setKey(key);

        assert(plaintext.equals(cast128.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});