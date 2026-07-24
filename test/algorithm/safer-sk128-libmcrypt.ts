
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own safer_sk128 module and running it.
// This library exists to read what mcrypt wrote, so agreement with libmcrypt
// is the property that matters. Most keys here contain bytes at or above
// 0x80: the single self test vector each cipher previously relied on used
// only low bytes, which is how a sign extension bug hid in Blowfish.
describe('safer-sk128 against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e2022242628', plaintext: 'b549e9590fc49edc', ciphertext: '08ff884d810f697e'},
        {key: '0a0c0e10121416181a1c1e2022242628', plaintext: 'c5967b4bc9d49d5a', ciphertext: 'd71cc255bdc1e5c0'},
        {key: '0a0c0e10121416181a1c1e2022242628', plaintext: '8d4707f57df85e52', ciphertext: 'e70e04b2ad33672c'},
        {key: '0a0c0e10121416181a1c1e2022242628', plaintext: 'ad6c144f1b3627a1', ciphertext: '960e41f707e42142'},
        {key: '0a0c0e10121416181a1c1e2022242628', plaintext: '4a10d162674340a2', ciphertext: 'ca8916657385bfc4'},
        {key: '096526e88726d790be3d1b8c213dc008', plaintext: '720f5e23a5a4c72f', ciphertext: '5894e55064d6e353'},
        {key: '9ef1eb00783a4362582fa3d2ff805440', plaintext: 'c13046075c546cb2', ciphertext: '0e31fbfa4db861a5'},
        {key: '44ab0e8c606952759f9441347fd82b16', plaintext: 'c20628aa2a6ab86a', ciphertext: '1765020fd607aa77'},
        {key: '679f2b416f108edb7b3159bc3bf78340', plaintext: 'ea3cbafd58a26011', ciphertext: 'a53f790c8f614684'},
        {key: 'a84df7d7168d11bc9a6a4ceeb0e9dbd7', plaintext: '43d84aced3babf34', ciphertext: '0562b5f086ab8c5b'},
        {key: 'fbdc8e96fee75bf8ea7b3486218714d2', plaintext: 'cf62cae78df6fe28', ciphertext: '6b10e0a99dc5f115'},
        {key: 'ec70500ce4714da729a50525dc053b9c', plaintext: 'f323f31f56152f84', ciphertext: '2a4d925e1a19c91b'},
        {key: 'f756fd5efecac4242f3d7bba17d1c897', plaintext: '5beac200a11c2ab4', ciphertext: '9c2ffbae75e24bb2'},
        {key: '509e6b339f0ed7aac490fa2fda22db91', plaintext: 'c492312cb6846759', ciphertext: '131c2000f24591f6'},
        {key: '2fad681d2f203d7ae0d3f6f962b40077', plaintext: '6401c5664ed97d79', ciphertext: '2c13e212a6cda971'},
        {key: '43e0684e57e855a5837be1b8b03e43dc', plaintext: '9c9756f2b85f8c41', ciphertext: 'addfc0162a99576b'},
        {key: 'a5a299c63d087278262b80cbb90ac7b1', plaintext: '520d71b5e93cb1a3', ciphertext: '8ac193042e20e6d8'},
        {key: '6b2e365141c150d09619598418392ece', plaintext: '379473a15d488f3d', ciphertext: '882a66b0d26d5526'},
        {key: 'a80c816cb991becf911681b8ad00e7e9', plaintext: '574a5e08a9b51712', ciphertext: '6050e5d091727f68'},
        {key: '47052b7767c2f6380ea1a49d9c03ea43', plaintext: 'c5fb8010b9ca5725', ciphertext: 'fe0d141657e4d207'},
        {key: '8c096a9ced223a20a1ab97bc6d810cfd', plaintext: '5dc8bdc812b2b851', ciphertext: '568389cc4a55464d'},
        {key: 'edfe3b883f646bd9f173638bc689fb69', plaintext: '9ad470bb8515a701', ciphertext: 'f2e0279bd4b8759c'},
        {key: '7dd60c5ef0b0fdb6e84b82d2062bac71', plaintext: 'bcf9bce3a9517ab9', ciphertext: 'fd4ebbd4138f420a'},
        {key: '9656d218da46a76d48f2abfb5455c1da', plaintext: '7e58531817aba7e9', ciphertext: 'd54fb2e8cb37e20e'},
        {key: 'f9276952052f7b597764adbe548a99aa', plaintext: 'a901498589214c88', ciphertext: 'cc7dba8d4d637d69'},
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
