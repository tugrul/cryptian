
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// Vectors produced by compiling libmcrypt's own cbc mode module and driving
// it with libmcrypt's cipher modules. Modes carry as much of the
// compatibility burden as the ciphers do, and mcrypt's names for them do not
// line up with anyone else's.
describe('cbc mode against libmcrypt', () => {

    describe('with Rijndael128', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd68c5197399e4b03890dab42b4214052d80bacf103f353139', iv: '7922ad250e3b950245008ae5801b3f75', plaintext: 'b850f8c6d9461e65f0a2e2df7fba056c', ciphertext: '0e0a1cb767effab49aec589bc2efe48d'},
            {key: '57d8c719ce35f5e90be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', iv: '59dea30e37b5fee582e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: 'fc7a02c6ee0db1d08ff07ce2231c9fed2d0f37e908c460f571ff6fb3ef61757d'},
            {key: '9cff0e72239ce9b5d7870d57b1cdce45dd4b5b0ae8c8939f4a66a7a291294d45', iv: '433d3e325a608b4685bce4c6782f368b', plaintext: '2bc8088cfe5f207d3e9dc35c9c78ea20243aeef4b4df989dc0ed92a41c7975c8179beef7a813716155284262d373fb0e', ciphertext: '2c50f79c558e301dbbab44d2971d8e3522d0821d2643dfaac4f6dc9935758d9a6d720ca8d61585f29b329384b59db1d7'},
            {key: 'd5395a8e387ecb1f9684387dab0d2a06103a296bf5c2a28e243cfc45b9cf145c', iv: 'f9dfeb8db97f7e7a59da20b558bd3bc2', plaintext: 'b93321415800edf741e3a27c76831a4eaf2b8e1efcf2379983bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd1827097389dade033e9', ciphertext: '5595c9e5aa2ae69dc0d35a262f547ae4539fa1ee046c631e77ff41df5439e5deb1a82a6899b07edcde12aef230215041649d67ac889f70c848c58758d81a52a9'},
            {key: '4903833121ab1b854f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf4', iv: '5c4d315b8c861efdbd0664e1289e8624', plaintext: 'ce43cb73f33ecac2a109bbd42b928d11d0815699507adab5afd18016ed43816af5c4336c7e3f87252beddfe408c3c216eab2519a9744c44e55b4246b9599947be11e6766865baab72666c653db149272', ciphertext: '1d5ed113d31d680e8d8cee19c76921405ec9af4c4632ab4a7c1732c5c6e476c560c985db5d18a0d24f02e8525ffa31061677ed25a14b19c508b740d30b10fd1e12b75e0ba82d866fb62654058c40462b'},
            {key: 'b73436242dc095c9fef19fcb4b88893c06c00496d55f7c51ba0be7548252ddcc', iv: 'be3cf4476bba3be4f29c2b4d62d3200c', plaintext: '3e5d212bd8600f56cfd2a017366f86c6', ciphertext: '22835ec4d6efa0ec6bbd668843f7b849'},
            {key: 'da7ce2ebbdc011faea402d791dd29e58abd2222d9fcb86d105e34b192d6c2049', iv: 'c4852640376f655701dd7c70e243ffca', plaintext: '1c9e552b5f173d41e288f7829c39d738e173ca6277755ba144e6e96591fc469c', ciphertext: 'a386d22de6a6b9120708ac4f939c89e69f199f42fc564af9c51f730273e1ee51'},
            {key: '9f003d3a14e61408bb3804a1168c683f73d9a07d1ce38a0019a3a3f39e38884e', iv: '1fe8850192dd28ead5c0231b0ca2ef94', plaintext: 'bfc8317509ffd2f3ed2e6600503bf931f66a9e0e4ad1102ff08f89c7cb9f4302ea81eaab558b3605d40733d9e4e9e0b3', ciphertext: 'ae1b9d9457f8016e407b6f64d109e1847589eb6f0f6589a4a26be1d44d3cb782903e31e1d3022761b03da7578d99864c'},
            {key: '368d841876783b3ae1b19c4f41538a05979b4baf3a11d65bc8a09f051b0c5321', iv: '67a02f56a952fdd050b2acd338ae6394', plaintext: 'b166c11d4ddb5a3a4da4fec297ad23a8f3e990c025c5280c97b59ae022bdcce39d6150048d43d1f3f32ebf0cd604deaeba4af379ea20ba0657b9708506c1b419', ciphertext: '63848e883263486a3bb674c5d364e5d0aa577c4df56bac3f37b7552a403b64493bdef8cfc05895b25c6904573ecd31f1c708ac45de2291df8a7c8807cdc68d79'},
            {key: '18c35064ce207eca50a47d174762038d0d99c45f0f861f587f2644f764551708', iv: 'c7f9126bd23e8fb2295faf0ac2822aa3', plaintext: '4750c80e123bfe6a16685da2f12f4574211195c5e8b52cc28e2cd5b3e0b5986cfc133a2ec96820d9b36e09ff19b4ad50730331cbd054f3f1c9e6752d7de1fff4326d4b24f7796bb33d0c241a91c3d414', ciphertext: '713cc141cdf304ccfbeb940427c15d174f23a3f778f33caba7ae78118f0aa252636a9a6d5f507c704649d79426962a90e42fa3f2fe196abcf28be5c2354e7f0856fbc2acb1b5d2b2aa91406bbbc87658'},
            {key: 'e1cbf81dbb9848aee36fdaec583732d398819eac07a1d9a3f2c636c908445646', iv: '32b99e1b8b950dba5f964ff447869217', plaintext: 'b5f69cb31b9f4178461366d3f8bbddef', ciphertext: '5b09753faf76ee6a36e7697341692462'},
            {key: '7104785b9e51414fe708be6c0d600b603ddbe602550beb922698c9c4eeab0365', iv: '32f93062686f53af9e71d8a2eb3e7514', plaintext: '84d156d8190d5d49fe2660ccc1b1de1d3ad98181c1d585f0d48623a58d17abaa', ciphertext: '54f00bceae491ce5e47a2c2b9f8f2744292a365b264984f8d4e6017223fb420b'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.cbc.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.cbc.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

    describe('with Des', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd', iv: '68c5197399e4b038', plaintext: '90dab42b4214052d', ciphertext: '56da2a7c5e991724'},
            {key: '80bacf103f353139', iv: '7922ad250e3b9502', plaintext: '45008ae5801b3f75b850f8c6d9461e65', ciphertext: 'f68a0e8822db9eed81505ed29d6f8577'},
            {key: 'f0a2e2df7fba056c', iv: '57d8c719ce35f5e9', plaintext: '0be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', ciphertext: '708c5952d4a3576a2a21a368a461645c8edf130f6cca36a0'},
            {key: '59dea30e37b5fee5', iv: '82e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: 'aa1a2327297ad021eab35d2b7c8d16f830f23bdce5c2dd523f763d92cb989a0e'},
            {key: '9cff0e72239ce9b5', iv: 'd7870d57b1cdce45', plaintext: 'dd4b5b0ae8c8939f4a66a7a291294d45433d3e325a608b4685bce4c6782f368b2bc8088cfe5f207d', ciphertext: 'b699b92197626c643a72ad66a2933b0ccff586de5090fbddda610006164821f6124009972acf3535'},
            {key: '3e9dc35c9c78ea20', iv: '243aeef4b4df989d', plaintext: 'c0ed92a41c7975c8', ciphertext: 'b5446c25a063937c'},
            {key: '179beef7a8137161', iv: '55284262d373fb0e', plaintext: 'd5395a8e387ecb1f9684387dab0d2a06', ciphertext: '68ee6a1a0aa70332770c68b405c31cb6'},
            {key: '103a296bf5c2a28e', iv: '243cfc45b9cf145c', plaintext: 'f9dfeb8db97f7e7a59da20b558bd3bc2b93321415800edf7', ciphertext: '63933da7d8fd7d5e37cf2742d3d4191031c2737550f61a06'},
            {key: '41e3a27c76831a4e', iv: 'af2b8e1efcf23799', plaintext: '83bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd182', ciphertext: '9d569d2fb82316e1d592ba3e9bcefded9f1213330714e7b5b7f8173c9269df21'},
            {key: '7097389dade033e9', iv: '4903833121ab1b85', plaintext: '4f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf45c4d315b8c861efdbd0664e1289e8624', ciphertext: 'be403ec43c17f4bc94e8efe4e52d6561b30988c847fa9ba032c8a3b31f6b6dc40480ffcea2bf173d'},
            {key: 'ce43cb73f33ecac2', iv: 'a109bbd42b928d11', plaintext: 'd0815699507adab5', ciphertext: 'de532d6597477882'},
            {key: 'afd18016ed43816a', iv: 'f5c4336c7e3f8725', plaintext: '2beddfe408c3c216eab2519a9744c44e', ciphertext: '210bfe47d17e552b20cee830e5462f67'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.cbc.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.cbc.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

});
