
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own rijndael-192 module and running it.
// These cover the 192 bit block Rijndael that AES never standardised, so libmcrypt is the only reference that can exist for it.
// Keys span the full byte range rather than the low half.
describe('rijndael-192 against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edcc5967b4bc9d49d5a8d4707f57df85e52', ciphertext: '3fae3fb7ad8a78de1a27c14261c639782ef84682b990d79c'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'ad6c144f1b3627a14a10d162674340a2096526e88726d790', ciphertext: 'fe95bfbfc98695c959ac54ddf854b78c8df49cd400f3f698'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'be3d1b8c213dc008720f5e23a5a4c72f9ef1eb00783a4362', ciphertext: 'e40ffebc49c67538d4ffc2bae6f812a6ac75650389bfeea8'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '582fa3d2ff805440c13046075c546cb244ab0e8c60695275', ciphertext: 'b2f965bb0ed589f6c17d80f31fa708fa983439801b6cd5ac'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '9f9441347fd82b16c20628aa2a6ab86a679f2b416f108edb', ciphertext: 'c434f92109b3df8388aab4a034048e382f5c32a8db0aa71a'},
        {key: '7b3159bc3bf78340ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd7', plaintext: '43d84aced3babf34fbdc8e96fee75bf8ea7b3486218714d2', ciphertext: '42ae5b0efc0d2bf65a690cdc04cf0d8b0fabc1100dae06c4'},
        {key: 'cf62cae78df6fe28ec70500ce4714da729a50525dc053b9cf323f31f56152f84', plaintext: 'f756fd5efecac4242f3d7bba17d1c8975beac200a11c2ab4', ciphertext: '3daa95d2d7ebb94f815b36c4912872845d60f0e60f89b827'},
        {key: '509e6b339f0ed7aac490fa2fda22db91c492312cb68467592fad681d2f203d7a', plaintext: 'e0d3f6f962b400776401c5664ed97d7943e0684e57e855a5', ciphertext: 'b955390088a223a3713c95eb9ab8ab2d6bb03d382fa016ac'},
        {key: '837be1b8b03e43dc9c9756f2b85f8c41a5a299c63d087278262b80cbb90ac7b1', plaintext: '520d71b5e93cb1a36b2e365141c150d09619598418392ece', ciphertext: '73b97fc4968cdf57fae395f7549c249bce707af13c5eda59'},
        {key: '379473a15d488f3da80c816cb991becf911681b8ad00e7e9574a5e08a9b51712', plaintext: '47052b7767c2f6380ea1a49d9c03ea43c5fb8010b9ca5725', ciphertext: '5744358bab5a106523cae25db8f064a1852a5ae267197d41'},
        {key: '8c096a9ced223a20a1ab97bc6d810cfd5dc8bdc812b2b851edfe3b883f646bd9', plaintext: 'f173638bc689fb699ad470bb8515a7017dd60c5ef0b0fdb6', ciphertext: '4f969accbed32a35a9b1cec829f5bb3ce99af01f071598a0'},
        {key: 'e84b82d2062bac71bcf9bce3a9517ab99656d218da46a76d48f2abfb5455c1da', plaintext: '7e58531817aba7e9f9276952052f7b597764adbe548a99aa', ciphertext: '1f43e812929e8f2522523141a98f438da02e1fe59d8cfeb3'},
        {key: 'a901498589214c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9', plaintext: 'ba1262900fc7da5042e970702fc7d7d4df7b2551ce14c215', ciphertext: '12329801d4eead9328d9d3e42643c182cdaba6fcd1cb0f9e'},
        {key: '52d1b661a03d17625f55a8578c1dba6aa202f4158b4206c182310a3ed73dba1a', plaintext: 'eafd05c2c2307ec9cfecd8458455d03ffd72d881df8a4e62', ciphertext: 'a723efc937a70eb6f3b3d5144591b50d13f5b3e91c2aa3b0'},
        {key: 'd2b47af64af88969e96cf8abd6cb1805cb0c669dc7bb6016c5bcd2201f34495b', plaintext: 'a10c68e936ccbb26ee4cce9672de951c72f2a0d353fc027c', ciphertext: 'c6acd749d5a483eafb8c44236f2d57f47a21c8b0f38f182f'},
        {key: 'a5268bcf342b1a92f15492f15439c1878a68b4fc6c4bf1e684a9b5a60d9ce498', plaintext: 'aab5a5a7a60436a8646382ae47595f8bbb9f1210da13458e', ciphertext: 'd895a9b303e79b269875eee194940c4217fc094f88371982'},
        {key: '1a35db25290659027f21591688006ce48be6570ebb5c3744761c65ffad433614', plaintext: 'b28845df6cb566bfeee2854c4236c97749443b9c67762de1', ciphertext: '37ed07296ed09e5c01a44b98fa2308f2f8356a35b78b41e5'},
        {key: '4e6882ff117c4c7d7a17ab93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12', plaintext: 'db084ad9c7ca7334233c91a67beb5372d5ad208e8d82a83b', ciphertext: 'dc5e6cc2d10628a3cc08ff3ea7e9d64f2d0032709fda242b'},
        {key: 'aa1c10e6a4caec18b903a525b4090ec4ca8b00a9ab64a9f2ab14842d5592850c', plaintext: '6260f0e52183b7551d751ab9600a8b2a29932125a198cc9d', ciphertext: '22324ab87fe7fefe3ae3f2456b3ac99b433fd9f55e51dfbe'},
        {key: '10e219e194230f0cafdda33a0e8f53bcf9b3b16b7344e76bc1fff6ba2856f92e', plaintext: '7302164a941693830eb11c294721362fea3e6334366a6a06', ciphertext: 'bff8844145bb4ec47af491610476562cb201dfa65b4958e5'},
        {key: 'c82f2614f14f24947d39e1191fa6746cc99b3f5bc78f904567c2435a4b29ec17', plaintext: '7a43d66c2d8de613fedf15275d6800ef390c02ec4eb96c33', ciphertext: '7e86eef43d84c142019f9b1ed848da0e76520952c971bd12'},
        {key: 'e5e9891d9001d399b9e67ead54d2089f41320a67660ef9b945cb195d23606229', plaintext: '702ca1fa917203140fea83536384ba40ac7040f9c42b318e', ciphertext: '190b1eeb9b4ef8f9af19cf68b614460ce647b989a21b3817'},
        {key: 'c1d5383882cf25cb453088d2af3555b0e2cd59ec5ce559c056dd618b96d8c8a2', plaintext: 'f0914c457d8b22573d23a22b2ada4d0662e323c40c575bfc', ciphertext: '0b3a7ddc425d6409034ea99bfdffbe16bcd03e49ed1e6394'},
        {key: '206d5a3fc85772e9e5e7e3505f958103a3527212f5c87aba51b1268e5414223e', plaintext: '38e0f10b3667e171afb760049d1292b83f82bf88d2b14cf1', ciphertext: 'a83deb52933ca435b4b3725a466905f1995f46f47479ef59'},
        {key: '5fd9ac15234fd82e926eb19df93c69bd0e13de296f5b23e8dbe385b2e80fd3fc', plaintext: 'ed15686bf18b4f83103dd4a293d30eeb8d5992f98c959506', ciphertext: 'fde376cd186b39c8930850e6ab83717b1f2e6fcc42c64338'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Rijndael192();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Rijndael192();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
