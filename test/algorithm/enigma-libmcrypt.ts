
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own enigma module and running it.
// This library exists to read what mcrypt wrote, so agreement with libmcrypt
// is the property that matters. Most keys here contain bytes at or above
// 0x80: the single self test vector each cipher previously relied on used
// only low bytes, which is how a sign extension bug hid in Blowfish.
describe('enigma against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e2022', plaintext: 'b549e9590fc49edc', ciphertext: '110a723dddcd81ec'},
        {key: '0a0c0e10121416181a1c1e2022', plaintext: 'c5967b4bc9d49d5a8d', ciphertext: 'b0071c22b9b27ca310'},
        {key: '0a0c0e10121416181a1c1e2022', plaintext: '4707f57df85e52ad6c14', ciphertext: '6c967816421ac0dee338'},
        {key: '0a0c0e10121416181a1c1e2022', plaintext: '4f1b3627a14a10d1626743', ciphertext: '6a99ff89ab65286147aff4'},
        {key: '0a0c0e10121416181a1c1e2022', plaintext: '40a2096526e88726d790be3d', ciphertext: '5c8148d588592bd921d200e9'},
        {key: '1b8c213dc008720f5e23a5a4c7', plaintext: '2f9ef1eb00783a4362582fa3d2', ciphertext: '58dd432b2cc226b5a19f3eb293'},
        {key: 'ff805440c13046075c546cb244', plaintext: 'ab0e8c606952759f9441347fd82b', ciphertext: '3b6a3efa680e231bcf1621e364c0'},
        {key: '16c20628aa2a6ab86a679f2b41', plaintext: '6f108edb7b3159bc3bf78340ea3cba', ciphertext: '6be95b9eaeb9f946ee9c4f3137e574'},
        {key: 'fd58a26011a84df7d7168d11bc', plaintext: '9a6a4ceeb0e9dbd743d84aced3babf34', ciphertext: 'ab16630119d4750f317296e3e9804b21'},
        {key: 'fbdc8e96fee75bf8ea7b348621', plaintext: '8714d2cf62cae78df6fe28ec70500ce471', ciphertext: 'fd9fad8bcb610d9e449810f6907924f1c1'},
        {key: '4da729a50525dc053b9cf323f3', plaintext: '1f56152f84f756fd5efecac4242f3d7bba17', ciphertext: '1659d00317811aab8e992b897ea8402109f2'},
        {key: 'd1c8975beac200a11c2ab4509e', plaintext: '6b339f0ed7aac490fa2fda22db91c492312cb6', ciphertext: '4f7e0a21b86c93f20f407245326292fdaf7c43'},
        {key: '8467592fad681d2f203d7ae0d3', plaintext: 'f6f962b400776401c5664ed97d7943e0684e57e8', ciphertext: 'bef8fad6eded751c1d92a18373d93940e87bc5cf'},
        {key: '55a5837be1b8b03e43dc9c9756', plaintext: 'f2b85f8c41a5a299c63d087278262b80cbb90ac7b1', ciphertext: '3dd7965f5a2f510a1290db2bb93f27534f08154070'},
        {key: '520d71b5e93cb1a36b2e365141', plaintext: 'c150d09619598418392ece379473a15d488f3da80c81', ciphertext: 'ea91600e58bb4eb34f9a2e3eb719f34e3cb2a295ae95'},
        {key: '6cb991becf911681b8ad00e7e9', plaintext: '574a5e08a9b5171247052b7767c2f6380ea1a49d9c03ea', ciphertext: 'e37a4dfa5162d16f58f79756266be34dc96650e0df9af8'},
        {key: '43c5fb8010b9ca57258c096a9c', plaintext: 'ed223a20a1ab97bc6d810cfd5dc8bdc812b2b851edfe3b88', ciphertext: '3a1b0419770231d777867c53bcdb096a9dcdb7b32fcd1a37'},
        {key: '3f646bd9f173638bc689fb699a', plaintext: 'd470bb8515a7017dd60c5ef0b0fdb6e84b82d2062bac71bcf9', ciphertext: '6d69706bec388effe29fc00f1184979489913fdd81ae624aae'},
        {key: 'bce3a9517ab99656d218da46a7', plaintext: '6d48f2abfb5455c1da7e58531817aba7e9f9276952052f7b5977', ciphertext: 'c8e77ed5ffbb61661ab396545150de1b620fdd866f883ccca3d4'},
        {key: '64adbe548a99aaa90149858921', plaintext: '4c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9ba', ciphertext: 'c7f29b3c8180b7eb81f2eafca7678a05bb5781e783b5ecdb6d622b'},
        {key: '1262900fc7da5042e970702fc7', plaintext: 'd7d4df7b2551ce14c21552d1b661a03d17625f55a8578c1dba6aa202', ciphertext: 'c3bf9606e3130812eff45b8328c9d698b6ab842a5f9584abef3859ce'},
        {key: 'f4158b4206c182310a3ed73dba', plaintext: '1aeafd05c2c2307ec9cfecd8458455d03ffd72d881df8a4e62d2b47af6', ciphertext: '7b805d25874afbded46114d7cf68e1b4b7e9c36e326d9b09d8688c2bd6'},
        {key: '4af88969e96cf8abd6cb1805cb', plaintext: '0c669dc7bb6016c5bcd2201f34495ba10c68e936ccbb26ee4cce9672de95', ciphertext: '80e58a6d8de783ceb9efadac38539a5b79860872cbee2c3d849a5094a6a1'},
        {key: '1c72f2a0d353fc027ca5268bcf', plaintext: '342b1a92f15492f15439c1878a68b4fc6c4bf1e684a9b5a60d9ce498aab5a5', ciphertext: '2a51efecba1d1f7a6f7379237cd05b1832662e3811e06de88057c8a6d7a8fd'},
        {key: 'a7a60436a8646382ae47595f8b', plaintext: 'bb9f1210da13458e', ciphertext: '23d78a708ff8b058'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Enigma();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Enigma();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
