
const {algorithm} = require('../..');
const assert = require('assert');

(typeof algorithm.Gost === 'function'? describe : describe.skip)
('gost', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('e498cf78cdf1d4a5', 'hex');

    const plaintext  = Buffer.from('0001020304050607', 'hex');


    it('should encrypt', () => {

        const gost = new algorithm.Gost();

        gost.setKey(key);

        assert(ciphertext.equals(gost.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    
    it('should decrypt', () => {

        const gost = new algorithm.Gost();

        gost.setKey(key);

        assert(plaintext.equals(gost.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});