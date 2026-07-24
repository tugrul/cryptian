
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own twofish module and running it.
// These cover Twofish. This implementation was written from the specification, so this checks it also agrees with the one mcrypt shipped.
// Keys span the full byte range rather than the low half.
describe('twofish against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edcc5967b4bc9d49d5a', ciphertext: '2bdc962a2974aaef3915171013124af6'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '8d4707f57df85e52ad6c144f1b3627a1', ciphertext: 'd9eb96554e38df37c210460c3e83a459'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4a10d162674340a2096526e88726d790', ciphertext: 'e86f266ae7eb0b74b7f72403ea1da407'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'be3d1b8c213dc008720f5e23a5a4c72f', ciphertext: 'b44872571fcee35369c906973da499c7'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '9ef1eb00783a4362582fa3d2ff805440', ciphertext: '895f1fc4c86799274a0f3e56d03fe63f'},
        {key: 'c13046075c546cb244ab0e8c606952759f9441347fd82b16c20628aa2a6ab86a', plaintext: '679f2b416f108edb7b3159bc3bf78340', ciphertext: 'a074b565519a846db1c54bbb0972a289'},
        {key: 'ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd743d84aced3babf34', plaintext: 'fbdc8e96fee75bf8ea7b3486218714d2', ciphertext: '9504bbf7b6fb95df991c6128f9b04a07'},
        {key: 'cf62cae78df6fe28ec70500ce4714da729a50525dc053b9cf323f31f56152f84', plaintext: 'f756fd5efecac4242f3d7bba17d1c897', ciphertext: 'f797f400a71ad022137273a1f2eb8bd8'},
        {key: '5beac200a11c2ab4509e6b339f0ed7aac490fa2fda22db91c492312cb6846759', plaintext: '2fad681d2f203d7ae0d3f6f962b40077', ciphertext: 'dc54129df47468e31982accad4cd1e8a'},
        {key: '6401c5664ed97d7943e0684e57e855a5837be1b8b03e43dc9c9756f2b85f8c41', plaintext: 'a5a299c63d087278262b80cbb90ac7b1', ciphertext: '1404d94efae5b2607776e1692b19108c'},
        {key: '520d71b5e93cb1a36b2e365141c150d09619598418392ece379473a15d488f3d', plaintext: 'a80c816cb991becf911681b8ad00e7e9', ciphertext: '523ff771cb48d735d22bcccc6ee52ca3'},
        {key: '574a5e08a9b5171247052b7767c2f6380ea1a49d9c03ea43c5fb8010b9ca5725', plaintext: '8c096a9ced223a20a1ab97bc6d810cfd', ciphertext: 'a7be6f7e67981501815bba974ec757b6'},
        {key: '5dc8bdc812b2b851edfe3b883f646bd9f173638bc689fb699ad470bb8515a701', plaintext: '7dd60c5ef0b0fdb6e84b82d2062bac71', ciphertext: '1582fabd287a9f6434f8f4fdff3c0c05'},
        {key: 'bcf9bce3a9517ab99656d218da46a76d48f2abfb5455c1da7e58531817aba7e9', plaintext: 'f9276952052f7b597764adbe548a99aa', ciphertext: 'cd6c3f815d25256c10847e47fa322203'},
        {key: 'a901498589214c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9', plaintext: 'ba1262900fc7da5042e970702fc7d7d4', ciphertext: '8f4fc36e9cc9e6cef595d324208b0d97'},
        {key: 'df7b2551ce14c21552d1b661a03d17625f55a8578c1dba6aa202f4158b4206c1', plaintext: '82310a3ed73dba1aeafd05c2c2307ec9', ciphertext: 'f4a488acc244ea5591669005d5cb9539'},
        {key: 'cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969e96cf8abd6cb1805', plaintext: 'cb0c669dc7bb6016c5bcd2201f34495b', ciphertext: '76133887ff9e95fdd7529f4ce15d67d6'},
        {key: 'a10c68e936ccbb26ee4cce9672de951c72f2a0d353fc027ca5268bcf342b1a92', plaintext: 'f15492f15439c1878a68b4fc6c4bf1e6', ciphertext: '2e9bede29424fee45287a1ab283ed3a4'},
        {key: '84a9b5a60d9ce498aab5a5a7a60436a8646382ae47595f8bbb9f1210da13458e', plaintext: '1a35db25290659027f21591688006ce4', ciphertext: '0f9c246c88f28f34d103b94ceaece0a2'},
        {key: '8be6570ebb5c3744761c65ffad433614b28845df6cb566bfeee2854c4236c977', plaintext: '49443b9c67762de14e6882ff117c4c7d', ciphertext: 'a740f6d528a97233ec0cd0c828617f59'},
        {key: '7a17ab93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca7334', plaintext: '233c91a67beb5372d5ad208e8d82a83b', ciphertext: '1d0e92f466f5b92c3cf77aefd77b7c4f'},
        {key: 'aa1c10e6a4caec18b903a525b4090ec4ca8b00a9ab64a9f2ab14842d5592850c', plaintext: '6260f0e52183b7551d751ab9600a8b2a', ciphertext: '848d37b8532a1fb8b139fc0277af40df'},
        {key: '29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3b16b7344e76b', plaintext: 'c1fff6ba2856f92e7302164a94169383', ciphertext: '2f9b6b5ef264b77883392514aae36d1d'},
        {key: '0eb11c294721362fea3e6334366a6a06c82f2614f14f24947d39e1191fa6746c', plaintext: 'c99b3f5bc78f904567c2435a4b29ec17', ciphertext: '8d78df615cf57d2509358b68cbfb87f8'},
        {key: '7a43d66c2d8de613fedf15275d6800ef390c02ec4eb96c33e5e9891d9001d399', plaintext: 'b9e67ead54d2089f41320a67660ef9b9', ciphertext: 'aa902c2f2a26bc7ec4222d5b0c779bdd'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Twofish();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Twofish();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
