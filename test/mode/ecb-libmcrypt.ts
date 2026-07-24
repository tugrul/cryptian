
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// Vectors produced by compiling libmcrypt's own ecb mode module and driving
// it with libmcrypt's cipher modules. Modes carry as much of the
// compatibility burden as the ciphers do, and mcrypt's names for them do not
// line up with anyone else's.
describe('ecb mode against libmcrypt', () => {

    describe('with Rijndael128', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd68c5197399e4b03890dab42b4214052d80bacf103f353139', iv: '7922ad250e3b950245008ae5801b3f75', plaintext: 'b850f8c6d9461e65f0a2e2df7fba056c', ciphertext: '03eb90b6333dafe3ff65c0414170483e'},
            {key: '57d8c719ce35f5e90be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', iv: '59dea30e37b5fee582e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '52b786c409d78469ca70c0b18e6f5fdaaeb4745e294e91d3c425281a2fe57d34'},
            {key: '9cff0e72239ce9b5d7870d57b1cdce45dd4b5b0ae8c8939f4a66a7a291294d45', iv: '433d3e325a608b4685bce4c6782f368b', plaintext: '2bc8088cfe5f207d3e9dc35c9c78ea20243aeef4b4df989dc0ed92a41c7975c8179beef7a813716155284262d373fb0e', ciphertext: 'd20edd7a67c2046a999b54dbd2be2683498b63f682492e7ac7724bede6c31a8de91edbf0f621d6fa3a1fc5ffa6f96aed'},
            {key: 'd5395a8e387ecb1f9684387dab0d2a06103a296bf5c2a28e243cfc45b9cf145c', iv: 'f9dfeb8db97f7e7a59da20b558bd3bc2', plaintext: 'b93321415800edf741e3a27c76831a4eaf2b8e1efcf2379983bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd1827097389dade033e9', ciphertext: '4499e581937f69b25db5093c131a31f93f8c87dd31f9ca7273ecd2ca46ec5cc1ca9612e8dbfc7bb9204aff13633880b34a0db6c5c178479e42e1fe8346f1bac2'},
            {key: '4903833121ab1b854f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf4', iv: '5c4d315b8c861efdbd0664e1289e8624', plaintext: 'ce43cb73f33ecac2a109bbd42b928d11d0815699507adab5afd18016ed43816af5c4336c7e3f87252beddfe408c3c216eab2519a9744c44e55b4246b9599947be11e6766865baab72666c653db149272', ciphertext: 'd8282d1eb829be75eea49ee77f7852ad35415f2b6350061fa3e415d3a302e75a9fe5333467fe79758c698305d3f99df945f229024f5a45605e7ba1d76d520dedf3dc8f441bccb0645f0d96b575951be3'},
            {key: 'b73436242dc095c9fef19fcb4b88893c06c00496d55f7c51ba0be7548252ddcc', iv: 'be3cf4476bba3be4f29c2b4d62d3200c', plaintext: '3e5d212bd8600f56cfd2a017366f86c6', ciphertext: '6e973f9d7eb2dfc1427a58fb5ed158c4'},
            {key: 'da7ce2ebbdc011faea402d791dd29e58abd2222d9fcb86d105e34b192d6c2049', iv: 'c4852640376f655701dd7c70e243ffca', plaintext: '1c9e552b5f173d41e288f7829c39d738e173ca6277755ba144e6e96591fc469c', ciphertext: '0bf67ec942e660c6d697ee89f8f6420e0d3868df4d672fc25013b1e57172e538'},
            {key: '9f003d3a14e61408bb3804a1168c683f73d9a07d1ce38a0019a3a3f39e38884e', iv: '1fe8850192dd28ead5c0231b0ca2ef94', plaintext: 'bfc8317509ffd2f3ed2e6600503bf931f66a9e0e4ad1102ff08f89c7cb9f4302ea81eaab558b3605d40733d9e4e9e0b3', ciphertext: 'f568c8691a3071713c94e99488999b0635c23990ed434795c43faa7c6cce4e403f52048a0db79eddd4c07b8f2153564f'},
            {key: '368d841876783b3ae1b19c4f41538a05979b4baf3a11d65bc8a09f051b0c5321', iv: '67a02f56a952fdd050b2acd338ae6394', plaintext: 'b166c11d4ddb5a3a4da4fec297ad23a8f3e990c025c5280c97b59ae022bdcce39d6150048d43d1f3f32ebf0cd604deaeba4af379ea20ba0657b9708506c1b419', ciphertext: 'c81360aa415f2daf89decfe8ab33c488260df9fecd6d46a1e29ef198bbe98b3df303fffdee2edbff01335d7426de57325a782a52b0129a2ed0dbb17ce3364486'},
            {key: '18c35064ce207eca50a47d174762038d0d99c45f0f861f587f2644f764551708', iv: 'c7f9126bd23e8fb2295faf0ac2822aa3', plaintext: '4750c80e123bfe6a16685da2f12f4574211195c5e8b52cc28e2cd5b3e0b5986cfc133a2ec96820d9b36e09ff19b4ad50730331cbd054f3f1c9e6752d7de1fff4326d4b24f7796bb33d0c241a91c3d414', ciphertext: 'fc22ed0e0362ab63e6aaa216345ce8448072b858e96e3cde3d17b2a7083c4f3822710291b6422b2eb48dee9fea741e1670eee9146738aae46370e480d8ba0309635de89df238d754f0c2093d85575fed'},
            {key: 'e1cbf81dbb9848aee36fdaec583732d398819eac07a1d9a3f2c636c908445646', iv: '32b99e1b8b950dba5f964ff447869217', plaintext: 'b5f69cb31b9f4178461366d3f8bbddef', ciphertext: '9b89bc1d5036b7bb99235f0403cecbaf'},
            {key: '7104785b9e51414fe708be6c0d600b603ddbe602550beb922698c9c4eeab0365', iv: '32f93062686f53af9e71d8a2eb3e7514', plaintext: '84d156d8190d5d49fe2660ccc1b1de1d3ad98181c1d585f0d48623a58d17abaa', ciphertext: '8a8f7ecbe2f17d563aee2b30c967541f9a6cbb9b4a299d058e5e69cae2b1d02e'},
        ];

        vectors.forEach(({key, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ecb.Cipher(cipher, Buffer.alloc(0))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ecb.Decipher(cipher, Buffer.alloc(0))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

    describe('with Des', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd', iv: '68c5197399e4b038', plaintext: '90dab42b4214052d', ciphertext: '979933c288253389'},
            {key: '80bacf103f353139', iv: '7922ad250e3b9502', plaintext: '45008ae5801b3f75b850f8c6d9461e65', ciphertext: '854e2e6571fe3642c890d39a1dfac7d4'},
            {key: 'f0a2e2df7fba056c', iv: '57d8c719ce35f5e9', plaintext: '0be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', ciphertext: '52aeadc8ad0cec8469cd659677b460695f0ab3f5c34d4d45'},
            {key: '59dea30e37b5fee5', iv: '82e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: 'c86e58f400f7ccbf39adf287c08bd4a4d856366984fed57a91fa258678fe8495'},
            {key: '9cff0e72239ce9b5', iv: 'd7870d57b1cdce45', plaintext: 'dd4b5b0ae8c8939f4a66a7a291294d45433d3e325a608b4685bce4c6782f368b2bc8088cfe5f207d', ciphertext: '4bc9dc87ce11c141e04b5e4445e76ff3bfbb5383e552840c66df09f2fc74e0751d46e9453ccd8008'},
            {key: '3e9dc35c9c78ea20', iv: '243aeef4b4df989d', plaintext: 'c0ed92a41c7975c8', ciphertext: '8661178ae11e5160'},
            {key: '179beef7a8137161', iv: '55284262d373fb0e', plaintext: 'd5395a8e387ecb1f9684387dab0d2a06', ciphertext: '894385c5114ac74d99f98f90ca365a1a'},
            {key: '103a296bf5c2a28e', iv: '243cfc45b9cf145c', plaintext: 'f9dfeb8db97f7e7a59da20b558bd3bc2b93321415800edf7', ciphertext: '637abe1cc60605007c0fce54ebf0295116a41696c67735dd'},
            {key: '41e3a27c76831a4e', iv: 'af2b8e1efcf23799', plaintext: '83bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd182', ciphertext: 'dd229a6f21b5ddab24e2cc3f8d2fe7c7c88add0030d0aafb641345852678ec9b'},
            {key: '7097389dade033e9', iv: '4903833121ab1b85', plaintext: '4f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf45c4d315b8c861efdbd0664e1289e8624', ciphertext: '8cc09dc267723ab899ff24d0d41dda366e5d89bc1e287131355148c9b53076c53c0255c2d24be6a3'},
            {key: 'ce43cb73f33ecac2', iv: 'a109bbd42b928d11', plaintext: 'd0815699507adab5', ciphertext: '7b037c3f186d2afb'},
            {key: 'afd18016ed43816a', iv: 'f5c4336c7e3f8725', plaintext: '2beddfe408c3c216eab2519a9744c44e', ciphertext: 'f4400f273a9321fb4e58678767ede47c'},
        ];

        vectors.forEach(({key, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ecb.Cipher(cipher, Buffer.alloc(0))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ecb.Decipher(cipher, Buffer.alloc(0))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

});
