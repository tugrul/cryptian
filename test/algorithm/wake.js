
const {algorithm} = require('../..');
const assert = require('assert');

(typeof algorithm.Wake === 'function'? describe : describe.skip)
('wake', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Wake === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = (i * 5 + 10) & 0xff;
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('434d575db053acfe6e4076f05298bedbd5f4f000be555d029b1367cffc7cd51bba61c76aa17da3530fb7d9', 'hex');

    const plaintext  = Buffer.from('05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f', 'hex');

    it('should encrypt', () => {

        const wake = new algorithm.Wake();

        wake.setKey(key);

        assert(ciphertext.equals(wake.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    it('should decrypt', () => {

        const wake = new algorithm.Wake();

        wake.setKey(key);

        assert(plaintext.equals(wake.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});

