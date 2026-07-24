
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own gost module and running it.
// These cover GOST with the substitution box set libmcrypt uses. Other GOST parameter sets, such as the one in the R 34.11-94 test data, give different output for the same key.
// Keys span the full byte range rather than the low half.
describe('gost against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edc', ciphertext: '9507090b63782162'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'c5967b4bc9d49d5a', ciphertext: 'ecb9472e2d79367f'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '8d4707f57df85e52', ciphertext: 'c7e61e9310b46b6f'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'ad6c144f1b3627a1', ciphertext: '84676ac1e536a9da'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4a10d162674340a2', ciphertext: 'd8ed8f28590fd39f'},
        {key: '096526e88726d790be3d1b8c213dc008720f5e23a5a4c72f9ef1eb00783a4362', plaintext: '582fa3d2ff805440', ciphertext: '786382004d0df974'},
        {key: 'c13046075c546cb244ab0e8c606952759f9441347fd82b16c20628aa2a6ab86a', plaintext: '679f2b416f108edb', ciphertext: '356069b7a4ef8aad'},
        {key: '7b3159bc3bf78340ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd7', plaintext: '43d84aced3babf34', ciphertext: '97b604b076c123ac'},
        {key: 'fbdc8e96fee75bf8ea7b3486218714d2cf62cae78df6fe28ec70500ce4714da7', plaintext: '29a50525dc053b9c', ciphertext: '5df18c0ebdea941b'},
        {key: 'f323f31f56152f84f756fd5efecac4242f3d7bba17d1c8975beac200a11c2ab4', plaintext: '509e6b339f0ed7aa', ciphertext: '6101902445b88503'},
        {key: 'c490fa2fda22db91c492312cb68467592fad681d2f203d7ae0d3f6f962b40077', plaintext: '6401c5664ed97d79', ciphertext: '3adda0b2f35b9b14'},
        {key: '43e0684e57e855a5837be1b8b03e43dc9c9756f2b85f8c41a5a299c63d087278', plaintext: '262b80cbb90ac7b1', ciphertext: '3fa6dd3cda7b60bb'},
        {key: '520d71b5e93cb1a36b2e365141c150d09619598418392ece379473a15d488f3d', plaintext: 'a80c816cb991becf', ciphertext: '84b5d9f1c75f162e'},
        {key: '911681b8ad00e7e9574a5e08a9b5171247052b7767c2f6380ea1a49d9c03ea43', plaintext: 'c5fb8010b9ca5725', ciphertext: '55aa2aca42dd73ca'},
        {key: '8c096a9ced223a20a1ab97bc6d810cfd5dc8bdc812b2b851edfe3b883f646bd9', plaintext: 'f173638bc689fb69', ciphertext: '9061cf64ba34e0c8'},
        {key: '9ad470bb8515a7017dd60c5ef0b0fdb6e84b82d2062bac71bcf9bce3a9517ab9', plaintext: '9656d218da46a76d', ciphertext: '095b1a7366a935db'},
        {key: '48f2abfb5455c1da7e58531817aba7e9f9276952052f7b597764adbe548a99aa', plaintext: 'a901498589214c88', ciphertext: '4e7cb1d6d0a7ff4c'},
        {key: '75a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9ba1262900fc7da50', plaintext: '42e970702fc7d7d4', ciphertext: 'b3317c984313fa4a'},
        {key: 'df7b2551ce14c21552d1b661a03d17625f55a8578c1dba6aa202f4158b4206c1', plaintext: '82310a3ed73dba1a', ciphertext: '86280041290d42ae'},
        {key: 'eafd05c2c2307ec9cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969', plaintext: 'e96cf8abd6cb1805', ciphertext: '4d92f771acaf559a'},
        {key: 'cb0c669dc7bb6016c5bcd2201f34495ba10c68e936ccbb26ee4cce9672de951c', plaintext: '72f2a0d353fc027c', ciphertext: '79a113306e16223e'},
        {key: 'a5268bcf342b1a92f15492f15439c1878a68b4fc6c4bf1e684a9b5a60d9ce498', plaintext: 'aab5a5a7a60436a8', ciphertext: '9575aaf94cfecc5e'},
        {key: '646382ae47595f8bbb9f1210da13458e1a35db25290659027f21591688006ce4', plaintext: '8be6570ebb5c3744', ciphertext: '93b3b0aae8380320'},
        {key: '761c65ffad433614b28845df6cb566bfeee2854c4236c97749443b9c67762de1', plaintext: '4e6882ff117c4c7d', ciphertext: '29076baac7ddc21f'},
        {key: '7a17ab93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca7334', plaintext: '233c91a67beb5372', ciphertext: '0514d39473805710'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Gost();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Gost();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
