
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own wake module and running it.
// This library exists to read what mcrypt wrote, so agreement with libmcrypt
// is the property that matters. Most keys here contain bytes at or above
// 0x80: the single self test vector each cipher previously relied on used
// only low bytes, which is how a sign extension bug hid in Blowfish.
describe('wake against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edc', ciphertext: '976dcf71a250c834'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'c5967b4bc9d49d5a8d', ciphertext: 'e7b25d639fc58dd639'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4707f57df85e52ad6c14', ciphertext: '6523d35557f9483215c7'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4f1b3627a14a10d1626743', ciphertext: '6d3f100f559db2c3244b25'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '40a2096526e88726d790be3d', ciphertext: '62862f4dadfef9946e8f8ad7'},
        {key: '1b8c213dc008720f5e23a5a4c72f9ef1eb00783a4362582fa3d2ff805440c130', plaintext: '46075c546cb244ab0e8c606952', ciphertext: '8128c2a5e6521426470a79d874'},
        {key: '759f9441347fd82b16c20628aa2a6ab86a679f2b416f108edb7b3159bc3bf783', plaintext: '40ea3cbafd58a26011a84df7d716', ciphertext: 'eac056021ad54a0e13e0ee680a47'},
        {key: '8d11bc9a6a4ceeb0e9dbd743d84aced3babf34fbdc8e96fee75bf8ea7b348621', plaintext: '8714d2cf62cae78df6fe28ec70500c', ciphertext: '5f5e1c1c59327591accc3790e922aa'},
        {key: 'e4714da729a50525dc053b9cf323f31f56152f84f756fd5efecac4242f3d7bba', plaintext: '17d1c8975beac200a11c2ab4509e6b33', ciphertext: 'e4f23b8821f43d8782e913eb58916633'},
        {key: '9f0ed7aac490fa2fda22db91c492312cb68467592fad681d2f203d7ae0d3f6f9', plaintext: '62b400776401c5664ed97d7943e0684e57', ciphertext: 'a626315bdb33769d103388d99b728e9774'},
        {key: 'e855a5837be1b8b03e43dc9c9756f2b85f8c41a5a299c63d087278262b80cbb9', plaintext: '0ac7b1520d71b5e93cb1a36b2e365141c150', ciphertext: '9d9143eae3d109533f8f6cfef8dfcc4047db'},
        {key: 'd09619598418392ece379473a15d488f3da80c816cb991becf911681b8ad00e7', plaintext: 'e9574a5e08a9b5171247052b7767c2f6380ea1', ciphertext: '480a02d168bd9dcd5dcf648157e826e238da55'},
        {key: 'a49d9c03ea43c5fb8010b9ca57258c096a9ced223a20a1ab97bc6d810cfd5dc8', plaintext: 'bdc812b2b851edfe3b883f646bd9f173638bc689', ciphertext: 'eaed9ebb2d5a5de4c93f610dda66221fb0d82a95'},
        {key: 'fb699ad470bb8515a7017dd60c5ef0b0fdb6e84b82d2062bac71bcf9bce3a951', plaintext: '7ab99656d218da46a76d48f2abfb5455c1da7e5853', ciphertext: '76e766e6822b642b7314a107db6d4c98df4ad142c3'},
        {key: '1817aba7e9f9276952052f7b597764adbe548a99aaa901498589214c8875a2b8', plaintext: 'b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9ba', ciphertext: 'ee24de469119475cb14e5ed2dc6aad25ee3dfd13e454'},
        {key: '1262900fc7da5042e970702fc7d7d4df7b2551ce14c21552d1b661a03d17625f', plaintext: '55a8578c1dba6aa202f4158b4206c182310a3ed73dba1a', ciphertext: '927f83539b9a2e1f76149ef9782151db15f2329457574e'},
        {key: 'eafd05c2c2307ec9cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969', plaintext: 'e96cf8abd6cb1805cb0c669dc7bb6016c5bcd2201f34495b', ciphertext: '6d392894d3e0c8202154fdbc477b0d975d2ba732210f686a'},
        {key: 'a10c68e936ccbb26ee4cce9672de951c72f2a0d353fc027ca5268bcf342b1a92', plaintext: 'f15492f15439c1878a68b4fc6c4bf1e684a9b5a60d9ce498aa', ciphertext: '838a07ed1da462ce1d0bdea59a029611ca5be86fd1eb18607a'},
        {key: 'b5a5a7a60436a8646382ae47595f8bbb9f1210da13458e1a35db25290659027f', plaintext: '21591688006ce48be6570ebb5c3744761c65ffad433614b28845', ciphertext: '78069d33a476755197f50a96f9af23d1ce8d449771df1b9712e9'},
        {key: 'df6cb566bfeee2854c4236c97749443b9c67762de14e6882ff117c4c7d7a17ab', plaintext: '93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca', ciphertext: 'e4ade7c3c68543e5bbb826a6b4d036f138b1f306cc3327b19446d4'},
        {key: '7334233c91a67beb5372d5ad208e8d82a83baa1c10e6a4caec18b903a525b409', plaintext: '0ec4ca8b00a9ab64a9f2ab14842d5592850c6260f0e52183b7551d75', ciphertext: '2e4a4709a624a2df6956b5e11fd2499b7d9ffca23e93e6d4a0922bcf'},
        {key: '1ab9600a8b2a29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3', plaintext: 'b16b7344e76bc1fff6ba2856f92e7302164a941693830eb11c29472136', ciphertext: '7df663a610c39414ab17cd570161aa8f4884ceeb88a3bd63ed4cc7bfb1'},
        {key: '2fea3e6334366a6a06c82f2614f14f24947d39e1191fa6746cc99b3f5bc78f90', plaintext: '4567c2435a4b29ec177a43d66c2d8de613fedf15275d6800ef390c02ec4e', ciphertext: '51968d6709f5b02b1f9c1a097bf6edb30138509b906a9a838746d6ab2ff7'},
        {key: 'b96c33e5e9891d9001d399b9e67ead54d2089f41320a67660ef9b945cb195d23', plaintext: '606229702ca1fa917203140fea83536384ba40ac7040f9c42b318ec1d53838', ciphertext: '861c84249cf8e19f1453c3c576afd0c8986f784d7a36cfce849dce95790de0'},
        {key: '82cf25cb453088d2af3555b0e2cd59ec5ce559c056dd618b96d8c8a2f0914c45', plaintext: '7d8b22573d23a22b', ciphertext: '9f467bbba9e6379f'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Wake();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Wake();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
