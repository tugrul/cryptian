
const {algorithm} = require('../..');
const assert = require('assert');

(typeof algorithm.Saferplus === 'function'? describe : describe.skip)
('saferplus', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('97fa76704bf6b578549f65c6f75b228b', 'hex');
    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');


    it('should encrypt', () => {

        const saferplus = new algorithm.Saferplus();

        saferplus.setKey(key);

        assert(ciphertext.equals(saferplus.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const saferplus = new algorithm.Saferplus();

        saferplus.setKey(key);

        assert(plaintext.equals(saferplus.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});

