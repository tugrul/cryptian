
const {algorithm} = require('../..');
const assert = require('assert');

(typeof algorithm.Arcfour === 'function'? describe : describe.skip)
('arcfour', () => {

    const key = Buffer.alloc(256, 0);

    for (let i = 0; i < 256; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('3abaa03a286e24c4196d292ab72934d6854c3eee', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f10111213', 'hex');


    it('should encrypt', () => {

        const arcfour = new algorithm.Arcfour();
        
        arcfour.setKey(key);

        assert(ciphertext.equals(arcfour.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });


    it('should decrypt', () => {

        const arcfour = new algorithm.Arcfour();
        
        arcfour.setKey(key);

        assert(plaintext.equals(arcfour.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });
    
});

