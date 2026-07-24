
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Vectors produced by compiling libmcrypt's own panama module and running it.
// Panama is a stream cipher, so each vector is a fresh key and a run of
// keystream over a plaintext of its own length. Keys span the full byte range.
describe('panama against libmcrypt', () => {

    const vectors = [
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'b549e9590fc49edc', ciphertext: '6226d778483f3509'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: 'c5967b4bc9d49d5a8d', ciphertext: '12f9456a8e2f368f4c'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4707f57df85e52ad6c14', ciphertext: '9068cb5cbfa5f978ad83'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '4f1b3627a14a10d1626743', ciphertext: '98740806e6b1bb04a3f096'},
        {key: '0a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042444648', plaintext: '40a2096526e88726d790be3d', ciphertext: '97cd374461132cf316076bfd'},
        {key: '1b8c213dc008720f5e23a5a4c72f9ef1eb00783a4362582fa3d2ff805440c130', plaintext: '46075c546cb244ab0e8c606952', ciphertext: '05a318c6dc8cbe846d25bc7fa0'},
        {key: '759f9441347fd82b16c20628aa2a6ab86a679f2b416f108edb7b3159bc3bf783', plaintext: '40ea3cbafd58a26011a84df7d716', ciphertext: 'dac43ea79d302fb377bcd4db7716'},
        {key: '8d11bc9a6a4ceeb0e9dbd743d84aced3babf34fbdc8e96fee75bf8ea7b348621', plaintext: '8714d2cf62cae78df6fe28ec70500c', ciphertext: '8dbebf5b6e655fcdd812df7fb03d23'},
        {key: 'e4714da729a50525dc053b9cf323f31f56152f84f756fd5efecac4242f3d7bba', plaintext: '17d1c8975beac200a11c2ab4509e6b33', ciphertext: '28721ce09de8e171b17cf56153bceca7'},
        {key: '9f0ed7aac490fa2fda22db91c492312cb68467592fad681d2f203d7ae0d3f6f9', plaintext: '62b400776401c5664ed97d7943e0684e57', ciphertext: '97a32f249782e7b3de9b266372b87598b0'},
        {key: 'e855a5837be1b8b03e43dc9c9756f2b85f8c41a5a299c63d087278262b80cbb9', plaintext: '0ac7b1520d71b5e93cb1a36b2e365141c150', ciphertext: '1a5c3343144c0c40b13c0f4659d2b72ac418'},
        {key: 'd09619598418392ece379473a15d488f3da80c816cb991becf911681b8ad00e7', plaintext: 'e9574a5e08a9b5171247052b7767c2f6380ea1', ciphertext: 'dd1a5664d9947ab27063773360f059b5f575a2'},
        {key: 'a49d9c03ea43c5fb8010b9ca57258c096a9ced223a20a1ab97bc6d810cfd5dc8', plaintext: 'bdc812b2b851edfe3b883f646bd9f173638bc689', ciphertext: '10b6810b161e72e07b9adadc711fe62a1d855539'},
        {key: 'fb699ad470bb8515a7017dd60c5ef0b0fdb6e84b82d2062bac71bcf9bce3a951', plaintext: '7ab99656d218da46a76d48f2abfb5455c1da7e5853', ciphertext: '051a8dcf990be807d14b75601feb0c1e3b48cbbb41'},
        {key: '1817aba7e9f9276952052f7b597764adbe548a99aaa901498589214c8875a2b8', plaintext: 'b753baeb4fb0f8e133dcaf7d9c6f77acd165aaa4e9ba', ciphertext: '2cde07b64ad909abedd2112915276bbb81c1159d00c2'},
        {key: '1262900fc7da5042e970702fc7d7d4df7b2551ce14c21552d1b661a03d17625f', plaintext: '55a8578c1dba6aa202f4158b4206c182310a3ed73dba1a', ciphertext: 'e50ca8bc3ecb5b60b358bfd4f9a5f59024dcd1a883efef'},
        {key: 'eafd05c2c2307ec9cfecd8458455d03ffd72d881df8a4e62d2b47af64af88969', plaintext: 'e96cf8abd6cb1805cb0c669dc7bb6016c5bcd2201f34495b', ciphertext: '89a932f1cd471cdd954eaf96a182b006d025f5ea160d5740'},
        {key: 'a10c68e936ccbb26ee4cce9672de951c72f2a0d353fc027ca5268bcf342b1a92', plaintext: 'f15492f15439c1878a68b4fc6c4bf1e684a9b5a60d9ce498aa', ciphertext: '28f100c64ddec70a50c0d9f9e69bd1c90c9d8d1b949690d67e'},
        {key: 'b5a5a7a60436a8646382ae47595f8bbb9f1210da13458e1a35db25290659027f', plaintext: '21591688006ce48be6570ebb5c3744761c65ffad433614b28845', ciphertext: '55674e20abc18b5e57cd99c2c46a603cc2a290db9341ffa05dbb'},
        {key: 'df6cb566bfeee2854c4236c97749443b9c67762de14e6882ff117c4c7d7a17ab', plaintext: '93e4a3f8d1d75dd5a3529e0ace55a71ae0a1c42b12db084ad9c7ca', ciphertext: '6df2a4e550f29c777b73e2910b47c02dc8204a32a6a9528aeab893'},
        {key: '7334233c91a67beb5372d5ad208e8d82a83baa1c10e6a4caec18b903a525b409', plaintext: '0ec4ca8b00a9ab64a9f2ab14842d5592850c6260f0e52183b7551d75', ciphertext: '07bf3e5164ddec568f0f20fa8fb8404059bd79462c4802256e0fa555'},
        {key: '1ab9600a8b2a29932125a198cc9d10e219e194230f0cafdda33a0e8f53bcf9b3', plaintext: 'b16b7344e76bc1fff6ba2856f92e7302164a941693830eb11c29472136', ciphertext: '1e537622b94d3774f0db67b9e3a1b068476662653a91f8c36134c44985'},
        {key: '2fea3e6334366a6a06c82f2614f14f24947d39e1191fa6746cc99b3f5bc78f90', plaintext: '4567c2435a4b29ec177a43d66c2d8de613fedf15275d6800ef390c02ec4e', ciphertext: '01d2526d93db4ed553eadb362be18c8aecf5bd912da433e1b4917567a821'},
        {key: 'b96c33e5e9891d9001d399b9e67ead54d2089f41320a67660ef9b945cb195d23', plaintext: '606229702ca1fa917203140fea83536384ba40ac7040f9c42b318ec1d53838', ciphertext: 'c167a3ccb61d6dca2976a17ac3d0efc05562cad3d7dc1e712e95638938fc8a'},
        {key: '82cf25cb453088d2af3555b0e2cd59ec5ce559c056dd618b96d8c8a2f0914c45', plaintext: '7d8b22573d23a22b', ciphertext: '83a2fa7bf1753b7e'},
    ];

    it('reports the sizes libmcrypt reports', () => {

        const panama = new algorithm.Panama();

        expect(panama.getKeySizes()).toEqual([32]);
        expect(panama.getIvSize()).toBe(32);
        expect(panama.getName()).toBe('panama');
    });

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const panama = new algorithm.Panama();
            panama.setKey(Buffer.from(key, 'hex'));

            expect(panama.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const panama = new algorithm.Panama();
            panama.setKey(Buffer.from(key, 'hex'));

            expect(panama.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
