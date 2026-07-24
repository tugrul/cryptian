
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own threeway module and running it.
// This library exists to read what mcrypt wrote, so agreement with libmcrypt
// is the property that matters. Most keys here contain bytes at or above
// 0x80: the single self test vector each cipher previously relied on used
// only low bytes, which is how a sign extension bug hid in Blowfish.
// Threeway defaults to the byte order of the original 3-Way, not the one
// libmcrypt used, so mcrypt compatibility needs setEndianCompat(true).
// Without it none of these vectors match.
describe('threeway against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20', plaintext: 'b549e9590fc49edcc5967b4b', ciphertext: '7949abd2cd7e327e967b46fa'},
        {key: '0a0c0e10121416181a1c1e20', plaintext: 'c9d49d5a8d4707f57df85e52', ciphertext: 'ced8e677f3f9480fbc86e9d3'},
        {key: '0a0c0e10121416181a1c1e20', plaintext: 'ad6c144f1b3627a14a10d162', ciphertext: '320029aa3928f021dc7bc14e'},
        {key: '0a0c0e10121416181a1c1e20', plaintext: '674340a2096526e88726d790', ciphertext: '01526ebc858a1186cd3b5531'},
        {key: '0a0c0e10121416181a1c1e20', plaintext: 'be3d1b8c213dc008720f5e23', ciphertext: 'b72e68d3ff0b2ba142d18266'},
        {key: 'a5a4c72f9ef1eb00783a4362', plaintext: '582fa3d2ff805440c1304607', ciphertext: 'd8a4699f105f79794a7de208'},
        {key: '5c546cb244ab0e8c60695275', plaintext: '9f9441347fd82b16c20628aa', ciphertext: '0750e73ad4d21b19246c0250'},
        {key: '2a6ab86a679f2b416f108edb', plaintext: '7b3159bc3bf78340ea3cbafd', ciphertext: '3073bfd1a2aebfe18169c492'},
        {key: '58a26011a84df7d7168d11bc', plaintext: '9a6a4ceeb0e9dbd743d84ace', ciphertext: '3a6d8c1b4285acaa4ebf62a6'},
        {key: 'd3babf34fbdc8e96fee75bf8', plaintext: 'ea7b3486218714d2cf62cae7', ciphertext: 'e041095a171df33b957071c8'},
        {key: '8df6fe28ec70500ce4714da7', plaintext: '29a50525dc053b9cf323f31f', ciphertext: '7dad681529440ef86f9568ac'},
        {key: '56152f84f756fd5efecac424', plaintext: '2f3d7bba17d1c8975beac200', ciphertext: '63774452178af831db1d4fca'},
        {key: 'a11c2ab4509e6b339f0ed7aa', plaintext: 'c490fa2fda22db91c492312c', ciphertext: '8a9394f8a81fb0c3929c8361'},
        {key: 'b68467592fad681d2f203d7a', plaintext: 'e0d3f6f962b400776401c566', ciphertext: '06dda0d51360755076c6a376'},
        {key: '4ed97d7943e0684e57e855a5', plaintext: '837be1b8b03e43dc9c9756f2', ciphertext: '90213e6a710cd4119b8241e3'},
        {key: 'b85f8c41a5a299c63d087278', plaintext: '262b80cbb90ac7b1520d71b5', ciphertext: '74ac4de168e3fa330bd86522'},
        {key: 'e93cb1a36b2e365141c150d0', plaintext: '9619598418392ece379473a1', ciphertext: 'c75f7823bdc49e97d02ba30a'},
        {key: '5d488f3da80c816cb991becf', plaintext: '911681b8ad00e7e9574a5e08', ciphertext: '031611186b7458f4e49ae47b'},
        {key: 'a9b5171247052b7767c2f638', plaintext: '0ea1a49d9c03ea43c5fb8010', ciphertext: 'e4c6473e3e5a91cd4724b639'},
        {key: 'b9ca57258c096a9ced223a20', plaintext: 'a1ab97bc6d810cfd5dc8bdc8', ciphertext: '27b81b4c3df7d27facd89c6f'},
        {key: '12b2b851edfe3b883f646bd9', plaintext: 'f173638bc689fb699ad470bb', ciphertext: '8b755d5defac206aa040d07a'},
        {key: '8515a7017dd60c5ef0b0fdb6', plaintext: 'e84b82d2062bac71bcf9bce3', ciphertext: 'ad44df404b78d2d15e96373c'},
        {key: 'a9517ab99656d218da46a76d', plaintext: '48f2abfb5455c1da7e585318', ciphertext: 'e78ca00261a86ba8bfbe441c'},
        {key: '17aba7e9f9276952052f7b59', plaintext: '7764adbe548a99aaa9014985', ciphertext: 'a27e2f3f65afb9e690453a04'},
        {key: '89214c8875a2b8b753baeb4f', plaintext: 'b0f8e133dcaf7d9c6f77acd1', ciphertext: 'b799bbbb5ec5d10299472cf1'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Threeway();
            cipher.setEndianCompat(true);
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Threeway();
            cipher.setEndianCompat(true);
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
