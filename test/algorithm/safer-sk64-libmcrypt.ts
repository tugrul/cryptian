
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own safer_sk64 module and running it.
// This library exists to read what mcrypt wrote, so agreement with libmcrypt
// is the property that matters. Most keys here contain bytes at or above
// 0x80: the single self test vector each cipher previously relied on used
// only low bytes, which is how a sign extension bug hid in Blowfish.
describe('safer-sk64 against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e1012141618', plaintext: 'b549e9590fc49edc', ciphertext: '543dae34f920de42'},
        {key: '0a0c0e1012141618', plaintext: 'c5967b4bc9d49d5a', ciphertext: 'a1f88c12bb09cdf7'},
        {key: '0a0c0e1012141618', plaintext: '8d4707f57df85e52', ciphertext: 'c6984ff4d32aab2a'},
        {key: '0a0c0e1012141618', plaintext: 'ad6c144f1b3627a1', ciphertext: 'ddf37c0460ca34fa'},
        {key: '0a0c0e1012141618', plaintext: '4a10d162674340a2', ciphertext: '0d175dd4afe2873e'},
        {key: '096526e88726d790', plaintext: 'be3d1b8c213dc008', ciphertext: '5a59a7c9e53dfb2c'},
        {key: '720f5e23a5a4c72f', plaintext: '9ef1eb00783a4362', ciphertext: '44298beaab91004c'},
        {key: '582fa3d2ff805440', plaintext: 'c13046075c546cb2', ciphertext: '002f9dd7588ed9a6'},
        {key: '44ab0e8c60695275', plaintext: '9f9441347fd82b16', ciphertext: '230ce6ed81dc3265'},
        {key: 'c20628aa2a6ab86a', plaintext: '679f2b416f108edb', ciphertext: 'c4690d2154787230'},
        {key: '7b3159bc3bf78340', plaintext: 'ea3cbafd58a26011', ciphertext: 'af67491bc6eab134'},
        {key: 'a84df7d7168d11bc', plaintext: '9a6a4ceeb0e9dbd7', ciphertext: '6db0903d9eaf0d06'},
        {key: '43d84aced3babf34', plaintext: 'fbdc8e96fee75bf8', ciphertext: '1c97a4c0427bbb86'},
        {key: 'ea7b3486218714d2', plaintext: 'cf62cae78df6fe28', ciphertext: '2ce19a2c8bc3ecbf'},
        {key: 'ec70500ce4714da7', plaintext: '29a50525dc053b9c', ciphertext: 'fa5c160a130838e4'},
        {key: 'f323f31f56152f84', plaintext: 'f756fd5efecac424', ciphertext: 'daa25308d7420557'},
        {key: '2f3d7bba17d1c897', plaintext: '5beac200a11c2ab4', ciphertext: '8a2edfd7084b2866'},
        {key: '509e6b339f0ed7aa', plaintext: 'c490fa2fda22db91', ciphertext: '0c9119e86b01411d'},
        {key: 'c492312cb6846759', plaintext: '2fad681d2f203d7a', ciphertext: '13ba4c22fe60d9e8'},
        {key: 'e0d3f6f962b40077', plaintext: '6401c5664ed97d79', ciphertext: '1dfa9926499b0b22'},
        {key: '43e0684e57e855a5', plaintext: '837be1b8b03e43dc', ciphertext: '865a6ccd6ebf6951'},
        {key: '9c9756f2b85f8c41', plaintext: 'a5a299c63d087278', ciphertext: '91990352dcc6bb2c'},
        {key: '262b80cbb90ac7b1', plaintext: '520d71b5e93cb1a3', ciphertext: '883b648d0d056971'},
        {key: '6b2e365141c150d0', plaintext: '9619598418392ece', ciphertext: '4adf43ab18e430bc'},
        {key: '379473a15d488f3d', plaintext: 'a80c816cb991becf', ciphertext: '7e757dabf1b8b799'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Safer();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Safer();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
