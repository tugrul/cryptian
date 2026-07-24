
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Panama with an initialization vector, checked against libmcrypt. Unlike
// arcfour, whose vector support libmcrypt leaves disabled behind a define,
// panama pushes the vector into its state as part of the key schedule, so
// this path is one that mcrypt data can actually depend on.
describe('panama with an initialization vector against libmcrypt', () => {

    const vectors = [
        {key: '7c3a6987af5b815fa1f17090cd2862181a46a2b3ab2a48fb33cb927d102abca4', iv: '95229632fbbd4ffb9e4aeb10c2e22f2216e1e900b3d465e3c1e9d3d125c9c0bc', plaintext: 'a0f2cfed850e5e92', ciphertext: '2102b36a24b3542d'},
        {key: '8768390828ea7ea6f74c18a47a2603d453bf01cdf8b10fdc89ffa768d25da3be', iv: '614c01b1d18d941a571eacdcba2fe963954eb2101650ccc7121b9a19704d4ae1', plaintext: '58cbdb24d10c93b6ce', ciphertext: '8fc1701bb48aaa6878'},
        {key: 'a22646c65eeeaf58d2d2b1d1f341e4096d8858b4e5286f4dad01a0c84a3fb8c3', iv: '7afc06272f0a71c611d71d9328be83c8dfa2ea88ca08d6624a276b43d1e03b3d', plaintext: '9b95e546fb0775ace43f', ciphertext: '5f0764deff53c24472d6'},
        {key: 'a411bd80c60288d1e60a1f53e2da8dba21d74127b3a27cdd7c2f57770dc27074', iv: 'ea74edbaff5315d7a05f161009d0c9dc6c015d60243cb88a7a884ef75694d1a1', plaintext: 'b1914f98697a32e035f8ed', ciphertext: 'dc6966fffb93d2f32695b0'},
        {key: '4019f2a984add03caa97b496ce6aa6e26955bab774779dc0906d03a6f7992f76', iv: '6f8addcff6351968fd46ba74bbc367a386e4db2a3944577d4e0062f52a56e32b', plaintext: '189c89a61b4bd114805efd33', ciphertext: '4e3320b076d3d65ffd5675c0'},
        {key: '677aa27b06f6f7c25168fe28ac7d1d6d3205954ce920cc6d8fa0b4f0a30b163d', iv: 'd8cdbf0519e317d811278da6362aceaeb60b2e364a656d45af97ad12cb6588ca', plaintext: '9db4c5dac884c899f2d35c4af9', ciphertext: '0ea222451250b0e3ed64c36b3f'},
        {key: '62007ad4cb858b00d629507b9fb519b215d78eb0df209fdbf83407fc8cc57c96', iv: 'a9a488dcce251554751e2b8418765c6b45a62e129c2441a15b50068b685d1cc0', plaintext: '7db7a9301ed07851b860079eb5f9', ciphertext: 'b72bac472f10c53930e3205caf9b'},
        {key: 'a4daf8669e31ca70d9248c88cb4f35443ac7b1ec05a62ea9552ceb3d766a8982', iv: 'ec870515b6994d9233c7f0c3a64f00da9410cea1795e8f251b30cd71efcd628e', plaintext: '02e4886c9c5d8e3c58b970cee0a454', ciphertext: '8541bc7a1ea49c32215a05bdfc2bb1'},
        {key: 'e02711517d23c61960bd20235ba4eb635f89f4c2c572cc5bf93f54b2f7fcd68d', iv: '4a6e0998e1db9f9481df4174765d13052518ea3a856940e146cd5987c9b45628', plaintext: '1b386fe766b613c8ec6ee97032b48b59', ciphertext: 'a4e47a879b0bd13c2a4e62d7326e2106'},
        {key: '47b3994fe8a6f22fe85264f8bc3d1aadd27274606f79f6ed08bd1a9a65736d39', iv: '456251463e7e83075164cfd9ac85d6a72f9b0ca8d7ce056f31500148170913e2', plaintext: '20f5739a44b6a25b7215ff042dd61f59b0', ciphertext: 'eadb48fa412220035c08f5462103743b92'},
        {key: '71d58edeb05f10d5edc8df2c1d7e4c055d83ff5b4ad5b3136ba93a5ede93afe9', iv: '95bb2045170205d5daa88008f2869778a4c8355a39704c9753b093c95021d243', plaintext: '58390f58f55623230236765522e8e82202c5', ciphertext: '8b9280c4d061f21616a2dab6f9b2ca71d7cc'},
        {key: 'cc4e25d1f23004ac9b006a474fbdf88527bd6ac7653f457bdec26d7c1472f6be', iv: 'd8b4033caf1f8a874844d87c1db4a4ef79914a11cb8c4c298af6552afad6fffa', plaintext: 'ffd0982dc0ecf316950d6251e215557355bdcb', ciphertext: 'b99b02ab2b82f843bacb59afbc08ffa651f77f'},
        {key: 'eecf7c8a2d97ca4d743b5bd6b88301c4ad469cbd7cb5230c9ba315dc9a89266a', iv: 'c4e156b86a21b4cc1c5c023ef69b071dbb6f18fbc1612d1601e8e07bfc47b49c', plaintext: '741a7be76ec0aeff76a38310829b9e2e658708da', ciphertext: '3277749575d502625b5a77803ef384aa1446e7dd'},
        {key: 'f0719276c7fc2ff6931dd216548eb7fe0cd9623781b879d8a0f8fb653a7bf05f', iv: '431186df35ef3d086649a159df493623ca184e3d955a5e504495ca9584c3ae18', plaintext: '3e86b2b36d97bc9a8f2be93da2d049857bcbd6863a', ciphertext: '1f20afb1befcfef96220749cd0641fe6bb85b450a3'},
        {key: 'e3fcd42f94431fd77380b42b037e6e244b5b01cd83dabce60ae0081dfcc60df9', iv: '9d48d1adbf278e1adc7f623994e16bc21873117fa10dbb4ee7e79f8cc726c1ef', plaintext: 'f874d9935279ff9af8aaf0c178298781d3246b360b46', ciphertext: 'c055494a42582ab8e31a3621cb8a932460c0d13ccd9a'},
    ];

    vectors.forEach(({key, iv, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const panama = new algorithm.Panama();
            panama.setKey(Buffer.from(key, 'hex'));
            panama.setIv(Buffer.from(iv, 'hex'));

            expect(panama.encrypt(Buffer.from(plaintext, 'hex')).toString('hex')).toBe(ciphertext);
        });

        it('decrypts vector ' + index, () => {

            const panama = new algorithm.Panama();
            panama.setKey(Buffer.from(key, 'hex'));
            panama.setIv(Buffer.from(iv, 'hex'));

            expect(panama.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex')).toBe(plaintext);
        });
    });
});
