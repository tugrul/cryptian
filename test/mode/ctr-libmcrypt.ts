
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// Vectors produced by compiling libmcrypt's own ctr mode module and driving
// it with libmcrypt's cipher modules. Modes carry as much of the
// compatibility burden as the ciphers do, and mcrypt's names for them do not
// line up with anyone else's.
describe('ctr mode against libmcrypt', () => {

    describe('with Rijndael128', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd68c5197399e4b03890dab42b4214052d80bacf103f353139', iv: '7922ad250e3b950245008ae5801b3f75', plaintext: 'b850f8c6d9461e65f0a2e2df7fba056c', ciphertext: '753a04208d581f23a6304261cae4340f'},
            {key: '57d8c719ce35f5e90be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', iv: '59dea30e37b5fee582e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '46c6ef3abdc7d42204c22db9b74d64f4657cdf673580f11a947163e7e078ab71'},
            {key: '9cff0e72239ce9b5d7870d57b1cdce45dd4b5b0ae8c8939f4a66a7a291294d45', iv: '433d3e325a608b4685bce4c6782f368b', plaintext: '2bc8088cfe5f207d3e9dc35c9c78ea20243aeef4b4df989dc0ed92a41c7975c8179beef7a813716155284262d373fb0e', ciphertext: '25bee06b99f2d6fe4259cd3f7fcafb7424f931335048ef5cae8c9c408d37bda1e28ddc8c503121c22d2198a800262c03'},
            {key: 'd5395a8e387ecb1f9684387dab0d2a06103a296bf5c2a28e243cfc45b9cf145c', iv: 'f9dfeb8db97f7e7a59da20b558bd3bc2', plaintext: 'b93321415800edf741e3a27c76831a4eaf2b8e1efcf2379983bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd1827097389dade033e9', ciphertext: 'deabc097d7999c04277b246d7a5c2980956fc8be73abcc0255d81fc58c0ecd81311e332dbccaf822117c93f3c4b87e4e6932563642f14d46eeb6745a21d8317d'},
            {key: '4903833121ab1b854f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf4', iv: '5c4d315b8c861efdbd0664e1289e8624', plaintext: 'ce43cb73f33ecac2a109bbd42b928d11d0815699507adab5afd18016ed43816af5c4336c7e3f87252beddfe408c3c216eab2519a9744c44e55b4246b9599947be11e6766865baab72666c653db149272', ciphertext: 'b0ee6582ee40f5fe80d02fa76386c182f07ebec0d98417922aaae21faec69c25a43cd9bca5f3cfd6fe0378c87915d09bef5dc84ee2c8849ba7a9e7bc39f7101f088ffff1bf05862950e19b4a9ac66f57'},
            {key: 'b73436242dc095c9fef19fcb4b88893c06c00496d55f7c51ba0be7548252ddcc', iv: 'be3cf4476bba3be4f29c2b4d62d3200c', plaintext: '3e5d212bd8600f56cfd2a017366f86c6', ciphertext: '7ddb712e62e0d955f934ae0f210b6188'},
            {key: 'da7ce2ebbdc011faea402d791dd29e58abd2222d9fcb86d105e34b192d6c2049', iv: 'c4852640376f655701dd7c70e243ffca', plaintext: '1c9e552b5f173d41e288f7829c39d738e173ca6277755ba144e6e96591fc469c', ciphertext: '9bbc56d6dcbe1532694712e51e4dc2252feb267dc5e83bbd1820d800d33d4f49'},
            {key: '9f003d3a14e61408bb3804a1168c683f73d9a07d1ce38a0019a3a3f39e38884e', iv: '1fe8850192dd28ead5c0231b0ca2ef94', plaintext: 'bfc8317509ffd2f3ed2e6600503bf931f66a9e0e4ad1102ff08f89c7cb9f4302ea81eaab558b3605d40733d9e4e9e0b3', ciphertext: '9f204f33595ac1e2ce254a7cf2aaf2f73c0ea9f4b4424ce0e70cff6bdeefd1d0a322ac0d58f47544d252d32222aa0ccf'},
            {key: '368d841876783b3ae1b19c4f41538a05979b4baf3a11d65bc8a09f051b0c5321', iv: '67a02f56a952fdd050b2acd338ae6394', plaintext: 'b166c11d4ddb5a3a4da4fec297ad23a8f3e990c025c5280c97b59ae022bdcce39d6150048d43d1f3f32ebf0cd604deaeba4af379ea20ba0657b9708506c1b419', ciphertext: 'abf5eada67d0c4dce368532c4094f4dd481b32fcbce0d25aa6c6155d6a1402ee90524cd9aa7d779d097bad858a884c1a78b8d1c6e3c2f42ffd4e1cfea7c7b014'},
            {key: '18c35064ce207eca50a47d174762038d0d99c45f0f861f587f2644f764551708', iv: 'c7f9126bd23e8fb2295faf0ac2822aa3', plaintext: '4750c80e123bfe6a16685da2f12f4574211195c5e8b52cc28e2cd5b3e0b5986cfc133a2ec96820d9b36e09ff19b4ad50730331cbd054f3f1c9e6752d7de1fff4326d4b24f7796bb33d0c241a91c3d414', ciphertext: 'c3273b3b0f926a425ac678b0c3e041d5c2361dbc2eaca1a85419396fc6fe31048a312d58d18aa4d961475189c63a9fb7d70e6d16b79e58b25f079524a6099cde32642a44826348b10fe004a7ad42d3c3'},
            {key: 'e1cbf81dbb9848aee36fdaec583732d398819eac07a1d9a3f2c636c908445646', iv: '32b99e1b8b950dba5f964ff447869217', plaintext: 'b5f69cb31b9f4178461366d3f8bbddef', ciphertext: '54186e82311bc33fb615b589c6441668'},
            {key: '7104785b9e51414fe708be6c0d600b603ddbe602550beb922698c9c4eeab0365', iv: '32f93062686f53af9e71d8a2eb3e7514', plaintext: '84d156d8190d5d49fe2660ccc1b1de1d3ad98181c1d585f0d48623a58d17abaa', ciphertext: '7431e0dad74a96b3282f50299d95206942e3edb36c5315df320d33b57b643fed'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ctr.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ctr.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

    describe('with Des', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd', iv: '68c5197399e4b038', plaintext: '90dab42b4214052d', ciphertext: '8f33b1dad1ce53ce'},
            {key: '80bacf103f353139', iv: '7922ad250e3b9502', plaintext: '45008ae5801b3f75b850f8c6d9461e65', ciphertext: '5b7d6429ff93ee5a25e863dbb16c1518'},
            {key: 'f0a2e2df7fba056c', iv: '57d8c719ce35f5e9', plaintext: '0be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', ciphertext: 'e1c7836905839c568f17fbf95483eea1d95433ae883aef91'},
            {key: '59dea30e37b5fee5', iv: '82e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '28f103cab22398b68daa835e59b495c9e9bbbec869ef5d73b8126dcb02d4cd21'},
            {key: '9cff0e72239ce9b5', iv: 'd7870d57b1cdce45', plaintext: 'dd4b5b0ae8c8939f4a66a7a291294d45433d3e325a608b4685bce4c6782f368b2bc8088cfe5f207d', ciphertext: 'd060b837a576b84f9208613bec4484cc409fc875a6adf48ad50cc1ec7e5dc0026756efb6859ab740'},
            {key: '3e9dc35c9c78ea20', iv: '243aeef4b4df989d', plaintext: 'c0ed92a41c7975c8', ciphertext: '28b6a0b024492c5f'},
            {key: '179beef7a8137161', iv: '55284262d373fb0e', plaintext: 'd5395a8e387ecb1f9684387dab0d2a06', ciphertext: '1184b3a6b9acbc58188fda8362069a15'},
            {key: '103a296bf5c2a28e', iv: '243cfc45b9cf145c', plaintext: 'f9dfeb8db97f7e7a59da20b558bd3bc2b93321415800edf7', ciphertext: '86d241fa7950aae3d414ef0058d1d2d12509104b64e85952'},
            {key: '41e3a27c76831a4e', iv: 'af2b8e1efcf23799', plaintext: '83bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd182', ciphertext: 'b3c18ba8dbd51c759268ccd756deaf075f8178e4c8f1fa2fd427f75e1733dfd8'},
            {key: '7097389dade033e9', iv: '4903833121ab1b85', plaintext: '4f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf45c4d315b8c861efdbd0664e1289e8624', ciphertext: '7b60bcadc276114d902bf31755c07293dc87b0d144f1c7993c4a2b756cf1aa3349c36d4db2d428e1'},
            {key: 'ce43cb73f33ecac2', iv: 'a109bbd42b928d11', plaintext: 'd0815699507adab5', ciphertext: '363088e57636d783'},
            {key: 'afd18016ed43816a', iv: 'f5c4336c7e3f8725', plaintext: '2beddfe408c3c216eab2519a9744c44e', ciphertext: '38ecfc2053e2e5958468ee16e0d6249c'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ctr.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ctr.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

});
