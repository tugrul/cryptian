
const {algorithm} = require('../..');
const assert = require('assert');

describe('des', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Des === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('a1502d70ba1320c8', 'hex');
    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const des = new algorithm.Des();
        
        des.setKey(key);

        assert(ciphertext.equals(des.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    
    it('should decrypt', () => {

        const des = new algorithm.Des();
        
        des.setKey(key);

        assert(plaintext.equals(des.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});