
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own serpent module and running it.
// These cover Serpent. This implementation was written from the specification, so this checks it also agrees with the one mcrypt shipped.
// Keys span the full byte range rather than the low half.
describe('serpent against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edcc5967b4bc9d49d5a', ciphertext: 'a5d45ee0b4e6a16b8b3ffa425aeba051'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '8d4707f57df85e52ad6c144f1b3627a1', ciphertext: 'd9ad7e053798cde9964861fffb3d215e'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4a10d162674340a2096526e88726d790', ciphertext: 'de3a2df3e891c2ad16cd9ea8b67dab04'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'be3d1b8c213dc008720f5e23a5a4c72f', ciphertext: '9e2a671ede6949d59122889cc9ad2b88'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '9ef1eb00783a4362582fa3d2ff805440', ciphertext: 'b55d4e7d98526fcd11819b30e803961c'},
        {key: 'c13046075c546cb244ab0e8c606952759f9441347fd82b16c20628aa2a6ab86a', plaintext: '679f2b416f108edb7b3159bc3bf78340', ciphertext: '1019c44f572a79405caf48e7862afd51'},
        {key: 'ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd743d84aced3babf34', plaintext: 'fbdc8e96fee75bf8ea7b3486218714d2', ciphertext: '5a5aae64e3cc9a2ce97e2d383f2b2761'},
        {key: 'cf62cae78df6fe28ec70500ce4714da729a50525dc053b9cf323f31f56152f84', plaintext: 'f756fd5efecac4242f3d7bba17d1c897', ciphertext: 'f0819d17cf12aa31df29ddba1ead259c'},
        {key: '5beac200a11c2ab4509e6b339f0ed7aac490fa2fda22db91c492312cb6846759', plaintext: '2fad681d2f203d7ae0d3f6f962b40077', ciphertext: 'a665530f0538b65bbf373c6f2d07d7f3'},
        {key: '6401c5664ed97d7943e0684e57e855a5837be1b8b03e43dc9c9756f2b85f8c41', plaintext: 'a5a299c63d087278262b80cbb90ac7b1', ciphertext: '0173b05d876663d98c0a0f72cbdd22bc'},
        {key: '520d71b5e93cb1a36b2e365141c150d09619598418392ece379473a15d488f3d', plaintext: 'a80c816cb991becf911681b8ad00e7e9', ciphertext: '8328b0b262e53d890340f231b89c6cc2'},
        {key: '574a5e08a9b5171247052b7767c2f6380ea1a49d9c03ea43c5fb8010b9ca5725', plaintext: '8c096a9ced223a20a1ab97bc6d810cfd', ciphertext: '26a016e4f5d3128a0841d8bfcfc255d8'},
        {key: '5dc8bdc812b2b851edfe3b883f646bd9f173638bc689fb699ad470bb8515a701', plaintext: '7dd60c5ef0b0fdb6e84b82d2062bac71', ciphertext: '125bd0b0cc2c50b1911f29ae2536a705'},
        {key: 'bcf9bce3a9517ab99656d218da46a76d48f2abfb5455c1da7e58531817aba7e9', plaintext: 'f9276952052f7b597764adbe548a99aa', ciphertext: '2a6a945c6c52466658b35325de3ca072'},
        {key: 'a901498589214c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9', plaintext: 'ba1262900fc7da5042e970702fc7d7d4', ciphertext: 'dd512f8fe5c7cfc512941bc48d48592b'},
        {key: 'df7b2551ce14c21552d1b661a03d17625f55a8578c1dba6aa202f4158b4206c1', plaintext: '82310a3ed73dba1aeafd05c2c2307ec9', ciphertext: 'a5cea62938552eafdf81a40be21707ff'},
        {key: 'cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969e96cf8abd6cb1805', plaintext: 'cb0c669dc7bb6016c5bcd2201f34495b', ciphertext: '597955a439a67475a36a7bbd5802f9f7'},
        {key: 'a10c68e936ccbb26ee4cce9672de951c72f2a0d353fc027ca5268bcf342b1a92', plaintext: 'f15492f15439c1878a68b4fc6c4bf1e6', ciphertext: '731b7c6247d511f338a3b1309fcfae34'},
        {key: '84a9b5a60d9ce498aab5a5a7a60436a8646382ae47595f8bbb9f1210da13458e', plaintext: '1a35db25290659027f21591688006ce4', ciphertext: 'b746cbff006b8ea61830f758a1bff97d'},
        {key: '8be6570ebb5c3744761c65ffad433614b28845df6cb566bfeee2854c4236c977', plaintext: '49443b9c67762de14e6882ff117c4c7d', ciphertext: '9eeb11e0b75ce6e6702f59402ff9dc61'},
        {key: '7a17ab93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca7334', plaintext: '233c91a67beb5372d5ad208e8d82a83b', ciphertext: '62ed1da9e551f209892427c2b37ef8fc'},
        {key: 'aa1c10e6a4caec18b903a525b4090ec4ca8b00a9ab64a9f2ab14842d5592850c', plaintext: '6260f0e52183b7551d751ab9600a8b2a', ciphertext: '5654ccf2233e75187fe3cdf85db47d79'},
        {key: '29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3b16b7344e76b', plaintext: 'c1fff6ba2856f92e7302164a94169383', ciphertext: '8b27bb6557b80ca0dd7d8044d9984d93'},
        {key: '0eb11c294721362fea3e6334366a6a06c82f2614f14f24947d39e1191fa6746c', plaintext: 'c99b3f5bc78f904567c2435a4b29ec17', ciphertext: '443fbea1501bae009b1cc72ed9e1e2a1'},
        {key: '7a43d66c2d8de613fedf15275d6800ef390c02ec4eb96c33e5e9891d9001d399', plaintext: 'b9e67ead54d2089f41320a67660ef9b9', ciphertext: 'e8b994b242affb2d102b0d86d69a4fc9'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Serpent();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Serpent();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
