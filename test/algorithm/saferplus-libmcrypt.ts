
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own saferplus module and running it.
// This library exists to read what mcrypt wrote, so agreement with libmcrypt
// is the property that matters. Most keys here contain bytes at or above
// 0x80: the single self test vector each cipher previously relied on used
// only low bytes, which is how a sign extension bug hid in Blowfish.
describe('saferplus against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edcc5967b4bc9d49d5a', ciphertext: 'bc7714479a91315b47a9a14ec403a93a'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '8d4707f57df85e52ad6c144f1b3627a1', ciphertext: 'e991e438853ccffde1950d73eabe83e2'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4a10d162674340a2096526e88726d790', ciphertext: '934308cd3315a22c007471f94f129f44'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'be3d1b8c213dc008720f5e23a5a4c72f', ciphertext: '19203761b247c8222f59a96f97fc9699'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '9ef1eb00783a4362582fa3d2ff805440', ciphertext: '0b8c6723329729e9418564560bf6c944'},
        {key: 'c13046075c546cb244ab0e8c606952759f9441347fd82b16c20628aa2a6ab86a', plaintext: '679f2b416f108edb7b3159bc3bf78340', ciphertext: '863b26cacf033bf8cf14a4ec4688314d'},
        {key: 'ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd743d84aced3babf34', plaintext: 'fbdc8e96fee75bf8ea7b3486218714d2', ciphertext: '706c1ff3a78c33f56991c0194593833a'},
        {key: 'cf62cae78df6fe28ec70500ce4714da729a50525dc053b9cf323f31f56152f84', plaintext: 'f756fd5efecac4242f3d7bba17d1c897', ciphertext: '09d7c21e192c4c19eae1b06d1f07b1ed'},
        {key: '5beac200a11c2ab4509e6b339f0ed7aac490fa2fda22db91c492312cb6846759', plaintext: '2fad681d2f203d7ae0d3f6f962b40077', ciphertext: '2518df213ece6be092050806fbe68a11'},
        {key: '6401c5664ed97d7943e0684e57e855a5837be1b8b03e43dc9c9756f2b85f8c41', plaintext: 'a5a299c63d087278262b80cbb90ac7b1', ciphertext: '655140043d21c353c1cc30c4c6c48e0e'},
        {key: '520d71b5e93cb1a36b2e365141c150d09619598418392ece379473a15d488f3d', plaintext: 'a80c816cb991becf911681b8ad00e7e9', ciphertext: '70f460bbdfdcbdb500e3c24c79ea66fc'},
        {key: '574a5e08a9b5171247052b7767c2f6380ea1a49d9c03ea43c5fb8010b9ca5725', plaintext: '8c096a9ced223a20a1ab97bc6d810cfd', ciphertext: '05e7a89cb34a0dfcaa3cfed73d833ac3'},
        {key: '5dc8bdc812b2b851edfe3b883f646bd9f173638bc689fb699ad470bb8515a701', plaintext: '7dd60c5ef0b0fdb6e84b82d2062bac71', ciphertext: '06d5fc69923745d6e7fb9876bef991b6'},
        {key: 'bcf9bce3a9517ab99656d218da46a76d48f2abfb5455c1da7e58531817aba7e9', plaintext: 'f9276952052f7b597764adbe548a99aa', ciphertext: '4caaa4a626120f8bae570993660dc126'},
        {key: 'a901498589214c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9', plaintext: 'ba1262900fc7da5042e970702fc7d7d4', ciphertext: 'be913ebcbdc094da1e4530c56a7a483d'},
        {key: 'df7b2551ce14c21552d1b661a03d17625f55a8578c1dba6aa202f4158b4206c1', plaintext: '82310a3ed73dba1aeafd05c2c2307ec9', ciphertext: 'b31013006fe53be5d9a3584283921a89'},
        {key: 'cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969e96cf8abd6cb1805', plaintext: 'cb0c669dc7bb6016c5bcd2201f34495b', ciphertext: '4aeffc0755cf02b2a6bf7ac7b5b0c120'},
        {key: 'a10c68e936ccbb26ee4cce9672de951c72f2a0d353fc027ca5268bcf342b1a92', plaintext: 'f15492f15439c1878a68b4fc6c4bf1e6', ciphertext: 'b67e385761ddf9582427d34eca3eeed6'},
        {key: '84a9b5a60d9ce498aab5a5a7a60436a8646382ae47595f8bbb9f1210da13458e', plaintext: '1a35db25290659027f21591688006ce4', ciphertext: 'bb380f83ebefa6eed4fd472b2802eddf'},
        {key: '8be6570ebb5c3744761c65ffad433614b28845df6cb566bfeee2854c4236c977', plaintext: '49443b9c67762de14e6882ff117c4c7d', ciphertext: '46d61c4cdf19f2e624cced5e9c0d523b'},
        {key: '7a17ab93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca7334', plaintext: '233c91a67beb5372d5ad208e8d82a83b', ciphertext: '14c7e938e5d613274e84972f0b5f94f9'},
        {key: 'aa1c10e6a4caec18b903a525b4090ec4ca8b00a9ab64a9f2ab14842d5592850c', plaintext: '6260f0e52183b7551d751ab9600a8b2a', ciphertext: '1c46b6602127e6cc49b35e5fa6d331bb'},
        {key: '29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3b16b7344e76b', plaintext: 'c1fff6ba2856f92e7302164a94169383', ciphertext: 'db72fc7c37382d2b5282fed0e35efae0'},
        {key: '0eb11c294721362fea3e6334366a6a06c82f2614f14f24947d39e1191fa6746c', plaintext: 'c99b3f5bc78f904567c2435a4b29ec17', ciphertext: 'df629d93eaf7fd9f1a6728b2b236c472'},
        {key: '7a43d66c2d8de613fedf15275d6800ef390c02ec4eb96c33e5e9891d9001d399', plaintext: 'b9e67ead54d2089f41320a67660ef9b9', ciphertext: 'c87d9916ce166c6b46bcb7b7724fe968'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Saferplus();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Saferplus();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
