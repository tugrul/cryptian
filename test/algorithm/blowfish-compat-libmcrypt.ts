
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own blowfish-compat module and running it.
// These cover MCRYPT_BLOWFISH_COMPAT, which is Blowfish with the other byte order.
// Keys span the full byte range rather than the low half.
describe('blowfish-compat against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e7072747678', plaintext: 'b549e9590fc49edc', ciphertext: '6ffbca5a2a0f272a'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e7072747678', plaintext: 'c5967b4bc9d49d5a', ciphertext: 'c5e1c366bdd7f029'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e7072747678', plaintext: '8d4707f57df85e52', ciphertext: '6e069e006c03558c'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e7072747678', plaintext: 'ad6c144f1b3627a1', ciphertext: '93c81d8bb70b0932'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e7072747678', plaintext: '4a10d162674340a2', ciphertext: 'c108f1232e012495'},
        {key: '096526e88726d790be3d1b8c213dc008720f5e23a5a4c72f9ef1eb00783a4362582fa3d2ff805440c13046075c546cb244ab0e8c60695275', plaintext: '9f9441347fd82b16', ciphertext: 'db2a6e9d9bb14ff9'},
        {key: 'c20628aa2a6ab86a679f2b416f108edb7b3159bc3bf78340ea3cbafd58a26011a84df7d7168d11bc9a6a4ceeb0e9dbd743d84aced3babf34', plaintext: 'fbdc8e96fee75bf8', ciphertext: 'd4373929c29f50ec'},
        {key: 'ea7b3486218714d2cf62cae78df6fe28ec70500ce4714da729a50525dc053b9cf323f31f56152f84f756fd5efecac4242f3d7bba17d1c897', plaintext: '5beac200a11c2ab4', ciphertext: 'd8ad81d4294e7478'},
        {key: '509e6b339f0ed7aac490fa2fda22db91c492312cb68467592fad681d2f203d7ae0d3f6f962b400776401c5664ed97d7943e0684e57e855a5', plaintext: '837be1b8b03e43dc', ciphertext: '8824e98c6a265ed0'},
        {key: '9c9756f2b85f8c41a5a299c63d087278262b80cbb90ac7b1520d71b5e93cb1a36b2e365141c150d09619598418392ece379473a15d488f3d', plaintext: 'a80c816cb991becf', ciphertext: 'be2d429cf5384926'},
        {key: '911681b8ad00e7e9574a5e08a9b5171247052b7767c2f6380ea1a49d9c03ea43c5fb8010b9ca57258c096a9ced223a20a1ab97bc6d810cfd', plaintext: '5dc8bdc812b2b851', ciphertext: 'c2089886b908dbde'},
        {key: 'edfe3b883f646bd9f173638bc689fb699ad470bb8515a7017dd60c5ef0b0fdb6e84b82d2062bac71bcf9bce3a9517ab99656d218da46a76d', plaintext: '48f2abfb5455c1da', ciphertext: 'a12cd818498be1f0'},
        {key: '7e58531817aba7e9f9276952052f7b597764adbe548a99aaa901498589214c8875a2b8b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9', plaintext: 'ba1262900fc7da50', ciphertext: '97694ba696aa9080'},
        {key: '42e970702fc7d7d4df7b2551ce14c21552d1b661a03d17625f55a8578c1dba6aa202f4158b4206c182310a3ed73dba1aeafd05c2c2307ec9', plaintext: 'cfecd8458455d03f', ciphertext: '6ec90b3bad5bbcb7'},
        {key: 'fd72d881df8a4e62d2b47af64af88969e96cf8abd6cb1805cb0c669dc7bb6016c5bcd2201f34495ba10c68e936ccbb26ee4cce9672de951c', plaintext: '72f2a0d353fc027c', ciphertext: '35b5b1edee6b1eec'},
        {key: 'a5268bcf342b1a92f15492f15439c1878a68b4fc6c4bf1e684a9b5a60d9ce498aab5a5a7a60436a8646382ae47595f8bbb9f1210da13458e', plaintext: '1a35db2529065902', ciphertext: 'f71f922ab873f6fb'},
        {key: '7f21591688006ce48be6570ebb5c3744761c65ffad433614b28845df6cb566bfeee2854c4236c97749443b9c67762de14e6882ff117c4c7d', plaintext: '7a17ab93e4a3f8d1', ciphertext: '6ed62ec4a1717b8b'},
        {key: 'd75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca7334233c91a67beb5372d5ad208e8d82a83baa1c10e6a4caec18b903a525b4090ec4', plaintext: 'ca8b00a9ab64a9f2', ciphertext: '65073c11deb8dd54'},
        {key: 'ab14842d5592850c6260f0e52183b7551d751ab9600a8b2a29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3b16b7344e76b', plaintext: 'c1fff6ba2856f92e', ciphertext: '57b85016894f4b50'},
        {key: '7302164a941693830eb11c294721362fea3e6334366a6a06c82f2614f14f24947d39e1191fa6746cc99b3f5bc78f904567c2435a4b29ec17', plaintext: '7a43d66c2d8de613', ciphertext: '97bb93ab8dd548bb'},
        {key: 'fedf15275d6800ef390c02ec4eb96c33e5e9891d9001d399b9e67ead54d2089f41320a67660ef9b945cb195d23606229702ca1fa91720314', plaintext: '0fea83536384ba40', ciphertext: '890c1c908a88000c'},
        {key: 'ac7040f9c42b318ec1d5383882cf25cb453088d2af3555b0e2cd59ec5ce559c056dd618b96d8c8a2f0914c457d8b22573d23a22b2ada4d06', plaintext: '62e323c40c575bfc', ciphertext: '9228d71032ad1f7a'},
        {key: '206d5a3fc85772e9e5e7e3505f958103a3527212f5c87aba51b1268e5414223e38e0f10b3667e171afb760049d1292b83f82bf88d2b14cf1', plaintext: '5fd9ac15234fd82e', ciphertext: 'c7e0b43daf0f9a97'},
        {key: '926eb19df93c69bd0e13de296f5b23e8dbe385b2e80fd3fced15686bf18b4f83103dd4a293d30eeb8d5992f98c959506dadc29979fb9b589', plaintext: '51c37d5e9dee90fa', ciphertext: '296fc26553a9d760'},
        {key: '90b52bc93d649a846b6e0a8d9e10cd6ac8638d7b91928d150d398553492f90e455e18641efe79ae8d4b1cc84b8bab8d626175cc20c24ed87', plaintext: 'f5951c6a85cbec76', ciphertext: '932a49885228f7cd'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Blowfish();
            cipher.setEndianCompat(true);
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Blowfish();
            cipher.setEndianCompat(true);
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
