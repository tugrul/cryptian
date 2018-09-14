
const {algorithm} = require('../..');
const assert = require('assert');

describe('rc2', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Rc2 === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('becbe4c8e6237a14', 'hex');
    const plaintext  = Buffer.from('0001020304050607', 'hex');


    it('should encrypt', () => {

        const rc2 = new algorithm.Rc2();

        rc2.setKey(key);

        assert(ciphertext.equals(rc2.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const rc2 = new algorithm.Rc2();

        rc2.setKey(key);

        assert(plaintext.equals(rc2.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});

