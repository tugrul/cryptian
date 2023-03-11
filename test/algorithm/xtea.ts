
import assert from "assert";

import cryptian from '../..';

const {Xtea} = cryptian.algorithm;
(typeof Xtea === 'function'? describe : describe.skip) ('xtea', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('f61e7ff6da7cdb27', 'hex');

    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const xtea = new Xtea();
        
        xtea.setKey(key);

        assert(ciphertext.equals(xtea.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const xtea = new Xtea();

        xtea.setKey(key);

        assert(plaintext.equals(xtea.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});