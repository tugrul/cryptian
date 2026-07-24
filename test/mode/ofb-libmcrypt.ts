
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm, mode} = cryptian;

// Vectors produced by compiling libmcrypt's own ofb mode module and driving
// it with libmcrypt's cipher modules. Modes carry as much of the
// compatibility burden as the ciphers do, and mcrypt's names for them do not
// line up with anyone else's.
// ofb here is the 8 bit variant. OpenSSL exposes no equivalent, so before
// these vectors existed this mode was checked against nothing at all.
describe('ofb mode against libmcrypt', () => {

    describe('with Rijndael128', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd68c5197399e4b03890dab42b4214052d80bacf103f353139', iv: '7922ad250e3b950245008ae5801b3f75', plaintext: 'b850f8c6d9461e65f0a2e2df7fba056c', ciphertext: '75cd2ed89299a38afd18a5ba801b6429'},
            {key: '57d8c719ce35f5e90be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', iv: '59dea30e37b5fee582e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '46c095a10a0c6f3095624de4547e66c42809bd05c64bef4063feaea2435e1786'},
            {key: '9cff0e72239ce9b5d7870d57b1cdce45dd4b5b0ae8c8939f4a66a7a291294d45', iv: '433d3e325a608b4685bce4c6782f368b', plaintext: '2bc8088cfe5f207d3e9dc35c9c78ea20243aeef4b4df989dc0ed92a41c7975c8179beef7a813716155284262d373fb0e', ciphertext: '25a8113a4530a3e233a7c91b14dba4a837d0ce6a2c75443e736570bd3ea90e750637401be85894d0eb13fcbb902c33ff'},
            {key: 'd5395a8e387ecb1f9684387dab0d2a06103a296bf5c2a28e243cfc45b9cf145c', iv: 'f9dfeb8db97f7e7a59da20b558bd3bc2', plaintext: 'b93321415800edf741e3a27c76831a4eaf2b8e1efcf2379983bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd1827097389dade033e9', ciphertext: 'de871de541f8e979f0e3ebe3efbf4f35a3974f1c144a165b084bfb9c47c6f378990ca00711a53ff090a3d25c99c423045fcdfc3f5d88f474a704ef65be45e94b'},
            {key: '4903833121ab1b854f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf4', iv: '5c4d315b8c861efdbd0664e1289e8624', plaintext: 'ce43cb73f33ecac2a109bbd42b928d11d0815699507adab5afd18016ed43816af5c4336c7e3f87252beddfe408c3c216eab2519a9744c44e55b4246b9599947be11e6766865baab72666c653db149272', ciphertext: 'b0d3fc6e06efe122efaa836c24d8e4db0bb1f8098b2a1d48f9be063eeb843ee518a58cf74ba0782b489054e492d627aaee5c440df17c587475ec06a2acd289b8b998c5bbca48159ad0821b795334133e'},
            {key: 'b73436242dc095c9fef19fcb4b88893c06c00496d55f7c51ba0be7548252ddcc', iv: 'be3cf4476bba3be4f29c2b4d62d3200c', plaintext: '3e5d212bd8600f56cfd2a017366f86c6', ciphertext: '7d6429bdfc454d09b434b6009e51e67a'},
            {key: 'da7ce2ebbdc011faea402d791dd29e58abd2222d9fcb86d105e34b192d6c2049', iv: 'c4852640376f655701dd7c70e243ffca', plaintext: '1c9e552b5f173d41e288f7829c39d738e173ca6277755ba144e6e96591fc469c', ciphertext: '9bb8f365cef3a6b8a8f752a23182a751859fabefff7fdf46a74e72b14738f62c'},
            {key: '9f003d3a14e61408bb3804a1168c683f73d9a07d1ce38a0019a3a3f39e38884e', iv: '1fe8850192dd28ead5c0231b0ca2ef94', plaintext: 'bfc8317509ffd2f3ed2e6600503bf931f66a9e0e4ad1102ff08f89c7cb9f4302ea81eaab558b3605d40733d9e4e9e0b3', ciphertext: '9febe9e095e129c7914f5ed958d7b5ddd1765dcd95733e1da8f18a16eab08d7506a8e5864964b2edcdd939549a06885c'},
            {key: '368d841876783b3ae1b19c4f41538a05979b4baf3a11d65bc8a09f051b0c5321', iv: '67a02f56a952fdd050b2acd338ae6394', plaintext: 'b166c11d4ddb5a3a4da4fec297ad23a8f3e990c025c5280c97b59ae022bdcce39d6150048d43d1f3f32ebf0cd604deaeba4af379ea20ba0657b9708506c1b419', ciphertext: 'ab4770cf4521db5ef8b761b5a0ca65e32072d21686cf4ffa24fec3cc64c2e0539dd251afa16280fa7900b412672205ba3f03037708b8136011ae3eac62c82fde'},
            {key: '18c35064ce207eca50a47d174762038d0d99c45f0f861f587f2644f764551708', iv: 'c7f9126bd23e8fb2295faf0ac2822aa3', plaintext: '4750c80e123bfe6a16685da2f12f4574211195c5e8b52cc28e2cd5b3e0b5986cfc133a2ec96820d9b36e09ff19b4ad50730331cbd054f3f1c9e6752d7de1fff4326d4b24f7796bb33d0c241a91c3d414', ciphertext: 'c3da31caa2566d0ca2a1d515b99cc85118142f4d9e936658ea2f1024dbef135870315be3e96c511c5874a94c5ac9ac9331da209bfb7a965e77143213705f901da0cfa37d765199cd86ad06594195c769'},
            {key: 'e1cbf81dbb9848aee36fdaec583732d398819eac07a1d9a3f2c636c908445646', iv: '32b99e1b8b950dba5f964ff447869217', plaintext: 'b5f69cb31b9f4178461366d3f8bbddef', ciphertext: '5481bb7090713a4323ecf9ebfbcb4942'},
            {key: '7104785b9e51414fe708be6c0d600b603ddbe602550beb922698c9c4eeab0365', iv: '32f93062686f53af9e71d8a2eb3e7514', plaintext: '84d156d8190d5d49fe2660ccc1b1de1d3ad98181c1d585f0d48623a58d17abaa', ciphertext: '74b0c05b70e7a608e7ac1493e3a9626ab27b60ad475f90038c4867f3762007be'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ofb.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Rijndael128();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ofb.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

    describe('with Des', () => {

        const vectors = [
            {key: '8de2a9e96a4caabd', iv: '68c5197399e4b038', plaintext: '90dab42b4214052d', ciphertext: '8fb18e224a1b7c8f'},
            {key: '80bacf103f353139', iv: '7922ad250e3b9502', plaintext: '45008ae5801b3f75b850f8c6d9461e65', ciphertext: '5bfe80f2ec775ddd8650f69b9342240b'},
            {key: 'f0a2e2df7fba056c', iv: '57d8c719ce35f5e9', plaintext: '0be5d5d75f427be3903ca6e8986cf3fbcb8f10ecf94c3e11', ciphertext: 'e1e9d36505d955ea8274a32c7017c990557178760f5932ed'},
            {key: '59dea30e37b5fee5', iv: '82e79f2f8d47962b', plaintext: '324e91f8a266a9fdadb67a38d94e18401eb91a86af6338df6dc0b9de89122522', ciphertext: '28b77e95bddafc881e19126508face8b7513e9527e570d5fc475921e037439b1'},
            {key: '9cff0e72239ce9b5', iv: 'd7870d57b1cdce45', plaintext: 'dd4b5b0ae8c8939f4a66a7a291294d45433d3e325a608b4685bce4c6782f368b2bc8088cfe5f207d', ciphertext: 'd0b6728c1d7d12edd70088cd667b5be10d3533d2fdce48388d331c478c0a5d391dd8e954f9519466'},
            {key: '3e9dc35c9c78ea20', iv: '243aeef4b4df989d', plaintext: 'c0ed92a41c7975c8', ciphertext: '2889256c6aa3c8e4'},
            {key: '179beef7a8137161', iv: '55284262d373fb0e', plaintext: 'd5395a8e387ecb1f9684387dab0d2a06', ciphertext: '1154d983324f20a1d7cf9c67872da6de'},
            {key: '103a296bf5c2a28e', iv: '243cfc45b9cf145c', plaintext: 'f9dfeb8db97f7e7a59da20b558bd3bc2b93321415800edf7', ciphertext: '86ef725c21bb233693bbf3f53256eedf33dc1b6ab4009f0e'},
            {key: '41e3a27c76831a4e', iv: 'af2b8e1efcf23799', plaintext: '83bea791f4453bf2562e265288b049e1e785c79cc85830c58db4262b108fd182', ciphertext: 'b353fb55f993342f70541c9741f7e767fbec81f9386d8c876d0a2d8897a8ae5d'},
            {key: '7097389dade033e9', iv: '4903833121ab1b85', plaintext: '4f4f8c49b481fe302a8da4ca4f235fea6139f2ada8fa5bf45c4d315b8c861efdbd0664e1289e8624', ciphertext: '7b88281e699ca763264f28fb3aada34fb103778c4bd6995c1484db00f99b90a8b222293612bdbc80'},
            {key: 'ce43cb73f33ecac2', iv: 'a109bbd42b928d11', plaintext: 'd0815699507adab5', ciphertext: '36cc03709fb7e239'},
            {key: 'afd18016ed43816a', iv: 'f5c4336c7e3f8725', plaintext: '2beddfe408c3c216eab2519a9744c44e', ciphertext: '3899c9878fdcb7c6c28247e9fb313882'},
        ];

        vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

            it('encrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ofb.Cipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
            });

            it('decrypts vector ' + index, () => {

                const cipher = new algorithm.Des();
                cipher.setKey(Buffer.from(key, 'hex'));

                expect(new mode.ofb.Decipher(cipher, Buffer.from(iv, 'hex'))
                    .transform(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
            });
        });
    });

});
