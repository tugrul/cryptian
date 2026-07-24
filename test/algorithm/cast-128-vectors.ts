
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Published CAST-128 vectors, restricted to the 128 bit key this cipher
// accepts. Shorter CAST keys use a reduced round count that mcrypt did not
// implement either.
// Taken from published test data rather than produced by this implementation,
// so they check the cipher against its specification and not against itself.
describe('cast128 published vectors', () => {

    const vectors = [
        {key: '0123456712345678234567893456789A', plaintext: '0123456789ABCDEF', ciphertext: '238B4FE5847E44B2'},
        {key: '51D35D2CFC978231CC8D404C05F20778', plaintext: '0D5ED4BF2C101A00', ciphertext: '851769123481EEBD'},
        {key: '3148F2F7A5EC9832C918B3FCE3A882D4', plaintext: 'D6AA8EAE1E559AAE', ciphertext: 'C7FAFAFC64204DDE'},
        {key: '23CA10AC5007672EAAC2A652A1033051', plaintext: 'F2504FFBB8970532', ciphertext: '6371C64A362D2A06'},
        {key: '69698114EB6B0C7DA021394E8294BA81', plaintext: '4B1E9D8F450B7342', ciphertext: '9CC2B912173553F3'},
        {key: 'E29067C7B82F2BB5787A95961C4B145B', plaintext: '26D7BA5E58E367FC', ciphertext: 'A2D1FCB23EDBE861'},
        {key: '724096996EA7E796847CC954DDB02F21', plaintext: '960370DF205DF0C9', ciphertext: 'E1F5DCA58544FE69'},
        {key: 'C44CD3B7C176A89B849AEC9D1A834D25', plaintext: '3E16104523173535', ciphertext: 'EF4B1D186287F9E4'},
        {key: 'F5A1E7B8DF1852E0A12E150665812CE1', plaintext: '6AB0B4F6FBDFE766', ciphertext: '273B54BDF2B5588C'},
        {key: '1BCBC553F08BA5AE3DC87E3A08D720A5', plaintext: '76300E213C3F9D73', ciphertext: '6C51876F5EA9CE03'},
        {key: '0265563A752CB548404FEBA1C7231FA7', plaintext: '22A5191C0722F0D8', ciphertext: 'F1E19892EE7A4E51'},
        {key: '9C553CF85065EC9EFE0A6526070DF766', plaintext: 'D20430D1B98AE949', ciphertext: '79E576FC40F1DC98'},
        {key: '1895E906311E100D6F189B0622248BC3', plaintext: '1C7401D639A47971', ciphertext: 'BD2172A2ED5F5C02'},
        {key: '616A2B2C30F26B1386CD8B1E9E15D77E', plaintext: 'B8591CA50C7E763D', ciphertext: '573F3DB3C43731FA'},
        {key: '14422858FA163B7C5267FF819773CE1D', plaintext: 'CDA3984E06CC637A', ciphertext: '2525D6596ACE9CD1'},
        {key: '172E65C14E746EE6203025E94171D520', plaintext: '5B5A603C9C090115', ciphertext: '3729DAB86CB1CCF7'},
        {key: '3E9FB858087C4E937A408EC1352482B1', plaintext: '9F9881CA42D7024C', ciphertext: '9C3C573D7B958521'},
        {key: 'A32E8B1498839F6017802758076B0BFC', plaintext: '4A5C46FD61058258', ciphertext: '2A1E5FD727F67F13'},
        {key: 'E303C6052387C310524721A2E461E89A', plaintext: 'EBBB828350790FDA', ciphertext: '78FC70F88D1622ED'},
        {key: '3B3DE3DA709304F69F1DD00F00A05064', plaintext: '5097EDFFDFC0CA5B', ciphertext: '3ABDD3B9A69C7330'},
        {key: 'C36EC561C6E005B5FC5F03F2A90B097E', plaintext: '8F950AE00DD2F279', ciphertext: '2C62AFD2C641CCE8'},
        {key: '202F39862076420EA9DF9DECCDC507AB', plaintext: 'D23B8A5E996E263D', ciphertext: '31A202CC0F9FB2B7'},
        {key: 'CCD6F6AAEEB788E928CECF99440BBF07', plaintext: '8D953359228A4C76', ciphertext: 'AA454DE10B7A6863'},
        {key: '017779EA29084F30B867FDDFF56A2158', plaintext: 'D2E9C19314726F4D', ciphertext: 'B744FAB9846F35E4'},
        {key: 'CE44271A18D709DCC62648F709C1CBE2', plaintext: 'F4C032C960A5B463', ciphertext: 'EDA7B0739A0638EE'},
        {key: 'B9F0598CFA6D4F92294C4BA43ED360F2', plaintext: '81A0FD9AA423ED36', ciphertext: 'C3CCCC1389F1D712'},
        {key: '5A6C06E02E3D5177D26F0D63DF839057', plaintext: 'B7E0072AE1CBEE65', ciphertext: 'AEF33EEDCCC2E47F'},
        {key: '547DF75C2FCFF20C1ED3A77AF1AD66E8', plaintext: 'F5810D9F1D639F82', ciphertext: 'A7A88EFA33ACF56E'},
        {key: '9CC9412E02C03D423E055D340BC74460', plaintext: '984A16BE2CD649AC', ciphertext: '444FC61F5CAB5A14'},
        {key: 'D2E4D28086A37BF2927C9477C8184907', plaintext: '8BC57E1C4D4DB959', ciphertext: '6AAFD5AD02B48AAD'},
        {key: 'AFE83744D296834750A5AEC59C1FA546', plaintext: 'E79C0E003AE33C71', ciphertext: 'DCD139EFE59F5B1B'},
        {key: 'B933E959F7D492EACA22E7DF1C179C79', plaintext: '5E8EB11FF48AE593', ciphertext: '947A1A1472AF838E'},
        {key: '6DC4F66D0812A820134C3F61E398195E', plaintext: 'FD9072FAB981B8AA', ciphertext: '57A9C621EF5BE045'},
        {key: '4FA0C134D50DDCAE2FA8828479149C61', plaintext: '53515B1ABC74C9FB', ciphertext: 'C87A6000F80DADAF'},
        {key: '7A6ECA7EAAF393694A32AF561FF7E056', plaintext: '1086DE79B6DC0C18', ciphertext: '102FFA93ECBB99CF'},
        {key: '42400F970D5E6E38DE297B365C0704D3', plaintext: '351228904431D12A', ciphertext: 'DC8B4548DA69C92D'},
        {key: '50D77ED75F69D9FD89C0B58A5374CC8E', plaintext: '889F00F0EC62610F', ciphertext: '3AEC2335A78EC8F9'},
        {key: '321E02B40C3F7D9D55A5135620685DC8', plaintext: '05CC553B50019A76', ciphertext: '7A3F48D2954FB957'},
        {key: 'DA1CA8F596F04697592CE210752FD08D', plaintext: 'D30DBA7A648B2CE9', ciphertext: '242C1509768F5F9E'},
        {key: '9C56B69695DB96CEDBF1133386D13768', plaintext: '1917132061B5B572', ciphertext: '28FDDE7607EBE08D'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Cast128();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex'))
                .toBe(ciphertext.toLowerCase());
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Cast128();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex'))
                .toBe(plaintext.toLowerCase());
        });
    });
});
