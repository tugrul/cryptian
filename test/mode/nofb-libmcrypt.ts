
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// Vectors produced by compiling libmcrypt's own nofb mode module and driving
// it with libmcrypt's cipher modules. Modes carry as much of the
// compatibility burden as the ciphers do, and mcrypt's names for them do not
// line up with anyone else's.
// nofb is the full block variant, which is what OpenSSL calls ofb.
describe('nofb mode against libmcrypt', () => {

    describe('with Rijndael128', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd68c5197399e4b03890dab42b4214052d80bacf103f353139', iv: '7922ad250e3b950245008ae5801b3f75', plaintext: 'b850f8c6d9461e65f0a2e2df7fba056c', ciphertext: '753a04208d581f23a6304261cae4340f'},
            {key: '57d8c719ce35f5e90be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', iv: '59dea30e37b5fee582e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '46c6ef3abdc7d42204c22db9b74d64f4740f896206cb98c14869e53bfcb652b4'},
            {key: '9cff0e72239ce9b5d7870d57b1cdce45dd4b5b0ae8c8939f4a66a7a291294d45', iv: '433d3e325a608b4685bce4c6782f368b', plaintext: '2bc8088cfe5f207d3e9dc35c9c78ea20243aeef4b4df989dc0ed92a41c7975c8179beef7a813716155284262d373fb0e', ciphertext: '25bee06b99f2d6fe4259cd3f7fcafb74b9e80434529a9977fcd1d1f3f6aa4db9783c15203177ccddb53b2288ae4ffc9d'},
            {key: 'd5395a8e387ecb1f9684387dab0d2a06103a296bf5c2a28e243cfc45b9cf145c', iv: 'f9dfeb8db97f7e7a59da20b558bd3bc2', plaintext: 'b93321415800edf741e3a27c76831a4eaf2b8e1efcf2379983bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd1827097389dade033e9', ciphertext: 'deabc097d7999c04277b246d7a5c2980e40eebda66211fc8fd2a9cf18229d5bb9298089f9fa0ef5b9525c5975f35b9d6cac7addcd22d698afafe153e043c453f'},
            {key: '4903833121ab1b854f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf4', iv: '5c4d315b8c861efdbd0664e1289e8624', plaintext: 'ce43cb73f33ecac2a109bbd42b928d11d0815699507adab5afd18016ed43816af5c4336c7e3f87252beddfe408c3c216eab2519a9744c44e55b4246b9599947be11e6766865baab72666c653db149272', ciphertext: 'b0ee6582ee40f5fe80d02fa76386c18212d8f00c25b49fdc2bb001bd6f847fc4a6ee89abea700674a67a8276e3a9474d57358b946d916948bd80c2092d1d38780afb6fdd9161f50544c469bc0dfdcd5c'},
            {key: 'b73436242dc095c9fef19fcb4b88893c06c00496d55f7c51ba0be7548252ddcc', iv: 'be3cf4476bba3be4f29c2b4d62d3200c', plaintext: '3e5d212bd8600f56cfd2a017366f86c6', ciphertext: '7ddb712e62e0d955f934ae0f210b6188'},
            {key: 'da7ce2ebbdc011faea402d791dd29e58abd2222d9fcb86d105e34b192d6c2049', iv: 'c4852640376f655701dd7c70e243ffca', plaintext: '1c9e552b5f173d41e288f7829c39d738e173ca6277755ba144e6e96591fc469c', ciphertext: '9bbc56d6dcbe1532694712e51e4dc225d4ef45ae01c8dd90e0a67e3513a34e2b'},
            {key: '9f003d3a14e61408bb3804a1168c683f73d9a07d1ce38a0019a3a3f39e38884e', iv: '1fe8850192dd28ead5c0231b0ca2ef94', plaintext: 'bfc8317509ffd2f3ed2e6600503bf931f66a9e0e4ad1102ff08f89c7cb9f4302ea81eaab558b3605d40733d9e4e9e0b3', ciphertext: '9f204f33595ac1e2ce254a7cf2aaf2f7a95341f4313bd19fcf603cbc75a9da6fd284e0a9fc2dac34bf255bb840c4f4f9'},
            {key: '368d841876783b3ae1b19c4f41538a05979b4baf3a11d65bc8a09f051b0c5321', iv: '67a02f56a952fdd050b2acd338ae6394', plaintext: 'b166c11d4ddb5a3a4da4fec297ad23a8f3e990c025c5280c97b59ae022bdcce39d6150048d43d1f3f32ebf0cd604deaeba4af379ea20ba0657b9708506c1b419', ciphertext: 'abf5eada67d0c4dce368532c4094f4dda4004e7caf71ebd5e7b91e17e8bebb308bd84a8e0182acb1bebbe46ed13d5460a84d2ba01ea81a9e5cf05c0573453116'},
            {key: '18c35064ce207eca50a47d174762038d0d99c45f0f861f587f2644f764551708', iv: 'c7f9126bd23e8fb2295faf0ac2822aa3', plaintext: '4750c80e123bfe6a16685da2f12f4574211195c5e8b52cc28e2cd5b3e0b5986cfc133a2ec96820d9b36e09ff19b4ad50730331cbd054f3f1c9e6752d7de1fff4326d4b24f7796bb33d0c241a91c3d414', ciphertext: 'c3273b3b0f926a425ac678b0c3e041d5acbefe1e3b3f90587d141b7df96febf31f67f9c1f91d3c5b6d04ef2f3eda6877da28a6f6ae3ab00c34362011664fa09b0e52549e26ade206d3db671540ae4202'},
            {key: 'e1cbf81dbb9848aee36fdaec583732d398819eac07a1d9a3f2c636c908445646', iv: '32b99e1b8b950dba5f964ff447869217', plaintext: 'b5f69cb31b9f4178461366d3f8bbddef', ciphertext: '54186e82311bc33fb615b589c6441668'},
            {key: '7104785b9e51414fe708be6c0d600b603ddbe602550beb922698c9c4eeab0365', iv: '32f93062686f53af9e71d8a2eb3e7514', plaintext: '84d156d8190d5d49fe2660ccc1b1de1d3ad98181c1d585f0d48623a58d17abaa', ciphertext: '7431e0dad74a96b3282f50299d9520694b468473a76b22665b1c4dbf1da7c8f7'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.nofb.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.nofb.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

    describe('with Des', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd', iv: '68c5197399e4b038', plaintext: '90dab42b4214052d', ciphertext: '8f33b1dad1ce53ce'},
            {key: '80bacf103f353139', iv: '7922ad250e3b9502', plaintext: '45008ae5801b3f75b850f8c6d9461e65', ciphertext: '5b7d6429ff93ee5a3cc4cc4b584cdeee'},
            {key: 'f0a2e2df7fba056c', iv: '57d8c719ce35f5e9', plaintext: '0be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', ciphertext: 'e1c7836905839c5691d1b967ac46ee2177e4b8e5c54ec647'},
            {key: '59dea30e37b5fee5', iv: '82e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '28f103cab22398b657802202f21dbd59a51c6d2c9e7a501e94abb83fa2e28cf6'},
            {key: '9cff0e72239ce9b5', iv: 'd7870d57b1cdce45', plaintext: 'dd4b5b0ae8c8939f4a66a7a291294d45433d3e325a608b4685bce4c6782f368b2bc8088cfe5f207d', ciphertext: 'd060b837a576b84f3bbaf0989be0e18304a1d2a80fa576893f1c220509709f90da0ff42d34488532'},
            {key: '3e9dc35c9c78ea20', iv: '243aeef4b4df989d', plaintext: 'c0ed92a41c7975c8', ciphertext: '28b6a0b024492c5f'},
            {key: '179beef7a8137161', iv: '55284262d373fb0e', plaintext: 'd5395a8e387ecb1f9684387dab0d2a06', ciphertext: '1184b3a6b9acbc585e249d8c1136b78c'},
            {key: '103a296bf5c2a28e', iv: '243cfc45b9cf145c', plaintext: 'f9dfeb8db97f7e7a59da20b558bd3bc2b93321415800edf7', ciphertext: '86d241fa7950aae3a941a8041be16c78b7ec1ca36610c2a7'},
            {key: '41e3a27c76831a4e', iv: 'af2b8e1efcf23799', plaintext: '83bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd182', ciphertext: 'b3c18ba8dbd51c75ea80d8c61afdd00bb1a1369757b572bc4777cca631ffec4e'},
            {key: '7097389dade033e9', iv: '4903833121ab1b85', plaintext: '4f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf45c4d315b8c861efdbd0664e1289e8624', ciphertext: '7b60bcadc276114d05f6769c03e608281355244357cbc3c2db4f713047e76538ce1ffa97d8751e24'},
            {key: 'ce43cb73f33ecac2', iv: 'a109bbd42b928d11', plaintext: 'd0815699507adab5', ciphertext: '363088e57636d783'},
            {key: 'afd18016ed43816a', iv: 'f5c4336c7e3f8725', plaintext: '2beddfe408c3c216eab2519a9744c44e', ciphertext: '38ecfc2053e2e5959220cf2d51b2964e'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.nofb.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.nofb.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

});
