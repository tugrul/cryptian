
import assert from "assert";

import cryptian from '../..';

const {Loki97} = cryptian.algorithm;


(typeof Loki97 === 'function'? describe : describe.skip) ('loki97', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('8cb28c958024bae27a94c698f96f12a9', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');

    it('should encrypt', () => {

        const loki97 = new Loki97();
        
        loki97.setKey(key);

        assert(ciphertext.equals(loki97.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    it('should decrypt', () => {

        const loki97 = new Loki97();
        
        loki97.setKey(key);

        assert(plaintext.equals(loki97.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});