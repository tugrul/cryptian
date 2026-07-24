
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own rijndael-256 module and running it.
// These cover the 256 bit block Rijndael that AES never standardised, so libmcrypt is the only reference that can exist for it.
// Keys span the full byte range rather than the low half.
describe('rijndael-256 against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edcc5967b4bc9d49d5a8d4707f57df85e52ad6c144f1b3627a1', ciphertext: 'be76ec10daf5468183d5a754492343145993510d1ec0f339d47899d70d875970'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4a10d162674340a2096526e88726d790be3d1b8c213dc008720f5e23a5a4c72f', ciphertext: 'e8a683a058083c7d3b00aae2317faf828dad33cc72ad2f5a443aee266c040b18'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '9ef1eb00783a4362582fa3d2ff805440c13046075c546cb244ab0e8c60695275', ciphertext: 'bc875a43d88d5f4438bdfe6146914c5fb572d3174e949ab1c3011dda59a23c77'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '9f9441347fd82b16c20628aa2a6ab86a679f2b416f108edb7b3159bc3bf78340', ciphertext: '51c02b49d63662dfe95f24d97f5fdd3b08748226094d9211cf0460a7e7688f1c'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd743d84aced3babf34', ciphertext: '6f8d7debebcbab90ff0e60344f5aa918bfeb765d10640835854dd375d2136389'},
        {key: 'fbdc8e96fee75bf8ea7b3486218714d2cf62cae78df6fe28ec70500ce4714da7', plaintext: '29a50525dc053b9cf323f31f56152f84f756fd5efecac4242f3d7bba17d1c897', ciphertext: '7159d7f0195da01ff9271b1845dc3f606cc5982f16835dbc2b71a3fae7690ad1'},
        {key: '5beac200a11c2ab4509e6b339f0ed7aac490fa2fda22db91c492312cb6846759', plaintext: '2fad681d2f203d7ae0d3f6f962b400776401c5664ed97d7943e0684e57e855a5', ciphertext: '27930b711f17463da17b3279b385e5c4de290bc2f483578f8a93ffff7900dc83'},
        {key: '837be1b8b03e43dc9c9756f2b85f8c41a5a299c63d087278262b80cbb90ac7b1', plaintext: '520d71b5e93cb1a36b2e365141c150d09619598418392ece379473a15d488f3d', ciphertext: '5a7df876cd91e8409b04c78e0c13b77d93e3b0c7a048f256278d389154302a35'},
        {key: 'a80c816cb991becf911681b8ad00e7e9574a5e08a9b5171247052b7767c2f638', plaintext: '0ea1a49d9c03ea43c5fb8010b9ca57258c096a9ced223a20a1ab97bc6d810cfd', ciphertext: '428e6ac09dab233344674f1d3ec0e81e4b55626cdf6f4e726f5dc2724d49a07e'},
        {key: '5dc8bdc812b2b851edfe3b883f646bd9f173638bc689fb699ad470bb8515a701', plaintext: '7dd60c5ef0b0fdb6e84b82d2062bac71bcf9bce3a9517ab99656d218da46a76d', ciphertext: '3946ade412136a51d25d5bb677235de490b42dee8f7722c18903a7652e5f98b5'},
        {key: '48f2abfb5455c1da7e58531817aba7e9f9276952052f7b597764adbe548a99aa', plaintext: 'a901498589214c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9', ciphertext: '11f36822aa96f10e8dff26610ebf0b5e9a7ebed609443030252f6b1573e92b31'},
        {key: 'ba1262900fc7da5042e970702fc7d7d4df7b2551ce14c21552d1b661a03d1762', plaintext: '5f55a8578c1dba6aa202f4158b4206c182310a3ed73dba1aeafd05c2c2307ec9', ciphertext: 'a97077a045c956b0f7c6b487a87b64ddcf949746f6732e85a5cd56e07b429f12'},
        {key: 'cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969e96cf8abd6cb1805', plaintext: 'cb0c669dc7bb6016c5bcd2201f34495ba10c68e936ccbb26ee4cce9672de951c', ciphertext: 'c574b623c80da2f1308333b7350e566e9ed61ac350ab869c8e8057f0520ea2fe'},
        {key: '72f2a0d353fc027ca5268bcf342b1a92f15492f15439c1878a68b4fc6c4bf1e6', plaintext: '84a9b5a60d9ce498aab5a5a7a60436a8646382ae47595f8bbb9f1210da13458e', ciphertext: '1bcdc4fee07262adf742193ed6e735fd0b16e913fba27f80004849392b35b3b5'},
        {key: '1a35db25290659027f21591688006ce48be6570ebb5c3744761c65ffad433614', plaintext: 'b28845df6cb566bfeee2854c4236c97749443b9c67762de14e6882ff117c4c7d', ciphertext: 'c886351bc5b54b200df6347a57a293763acf6f1997ae5bf04f0b0a7aafe7f1d0'},
        {key: '7a17ab93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca7334', plaintext: '233c91a67beb5372d5ad208e8d82a83baa1c10e6a4caec18b903a525b4090ec4', ciphertext: 'e0e1a890b3e2d440e5b136c4aae508bd2526cd701c83701af19b18d82eab00f5'},
        {key: 'ca8b00a9ab64a9f2ab14842d5592850c6260f0e52183b7551d751ab9600a8b2a', plaintext: '29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3b16b7344e76b', ciphertext: '49a9e1c89a168c1fed9f8a45a9f73f7105a5f4502ad69575c4d4b6ed0b9c2b2c'},
        {key: 'c1fff6ba2856f92e7302164a941693830eb11c294721362fea3e6334366a6a06', plaintext: 'c82f2614f14f24947d39e1191fa6746cc99b3f5bc78f904567c2435a4b29ec17', ciphertext: '167558e43e5526cca328cc918a00d8577710ba0b187693af18bd4cbf8ae59683'},
        {key: '7a43d66c2d8de613fedf15275d6800ef390c02ec4eb96c33e5e9891d9001d399', plaintext: 'b9e67ead54d2089f41320a67660ef9b945cb195d23606229702ca1fa91720314', ciphertext: '5e80d0ba8d94e22a4cc97057afcd48778644ae9870095023e32f931531747a1c'},
        {key: '0fea83536384ba40ac7040f9c42b318ec1d5383882cf25cb453088d2af3555b0', plaintext: 'e2cd59ec5ce559c056dd618b96d8c8a2f0914c457d8b22573d23a22b2ada4d06', ciphertext: '73282c532dcdf9a83f3ba466b7dfe53b8751d12ac66bad1363eeb5d0b8d3b426'},
        {key: '62e323c40c575bfc206d5a3fc85772e9e5e7e3505f958103a3527212f5c87aba', plaintext: '51b1268e5414223e38e0f10b3667e171afb760049d1292b83f82bf88d2b14cf1', ciphertext: 'c07b2e7a0b1570ffd4b1332e7812c39d9ca487db79c68b302256bfff13f5c021'},
        {key: '5fd9ac15234fd82e926eb19df93c69bd0e13de296f5b23e8dbe385b2e80fd3fc', plaintext: 'ed15686bf18b4f83103dd4a293d30eeb8d5992f98c959506dadc29979fb9b589', ciphertext: '95137240b93d760edd56e7e68a557c85ee82290e80c08013b1f1b3515e24b7fe'},
        {key: '51c37d5e9dee90fa90b52bc93d649a846b6e0a8d9e10cd6ac8638d7b91928d15', plaintext: '0d398553492f90e455e18641efe79ae8d4b1cc84b8bab8d626175cc20c24ed87', ciphertext: '32ef976cb67c73a693e0fa70c7bd082c56fb3800b43afc00a3a7308b605361a0'},
        {key: 'f5951c6a85cbec76b16e67b429034d2ebc9df6733858070553ffe12e498bbe2f', plaintext: '6cf429779236edbc91537930ca305b44db2d917ca9c7f278a83ced5cc6933551', ciphertext: '630d683a8482508afcb8935c12b857ecc6883c60781b68387c7942607dc5c9a5'},
        {key: '63dfe61eef7b5081b5872737661aca26c2b6824fb79b52e77819059ec996b841', plaintext: '0f2ec62a50af21a3a1c0f383aa4e49764d2812ab84d7974b38411945c4fc0510', ciphertext: 'a09bcd39ba9bfbfcc43f74695c66ee2a17a1abef9d54686a79c214c823e8c653'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Rijndael256();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Rijndael256();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
