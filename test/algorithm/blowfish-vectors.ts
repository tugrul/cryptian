
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Published Blowfish vectors. Many of these keys contain bytes at or above
// 0x80, which is exactly what the signed char key indexing used to corrupt.
// Taken from published test data rather than produced by this implementation,
// so they check the cipher against its specification and not against itself.
describe('blowfish published vectors', () => {

    const vectors = [
        {key: '0123456789ABCDEF', plaintext: '0000000000000000', ciphertext: '245946885754369A'},
        {key: '0000000000000000', plaintext: '0000000000000000', ciphertext: '4EF997456198DD78'},
        {key: 'FFFFFFFFFFFFFFFF', plaintext: '0000000000000000', ciphertext: 'F21E9A77B71C49BC'},
        {key: '584023641ABA6176', plaintext: '004BD6EF09176062', ciphertext: '452031C1E4FADA8E'},
        {key: 'FEDCBA9876543210', plaintext: '0123456789ABCDEF', ciphertext: '0ACEAB0FC6A0A28D'},
        {key: '1111111111111111', plaintext: '0123456789ABCDEF', ciphertext: '7D0CC630AFDA1EC7'},
        {key: '1F1F1F1F0E0E0E0E', plaintext: '0123456789ABCDEF', ciphertext: 'A790795108EA3CAE'},
        {key: 'E0FEE0FEF1FEF1FE', plaintext: '0123456789ABCDEF', ciphertext: 'C39E072D9FAC631D'},
        {key: '0101010101010101', plaintext: '0123456789ABCDEF', ciphertext: 'FA34EC4847B268B2'},
        {key: '7CA110454A1A6E57', plaintext: '01A1D6D039776742', ciphertext: '59C68245EB05282B'},
        {key: '07A1133E4A0B2686', plaintext: '0248D43806F67172', ciphertext: '1730E5778BEA1DA4'},
        {key: '49E95D6D4CA229BF', plaintext: '02FE55778117F12A', ciphertext: 'CF9C5D7A4986ADB5'},
        {key: '0113B970FD34F2CE', plaintext: '059B5E0851CF143A', ciphertext: '48F4D0884C379918'},
        {key: '4FB05E1515AB73A7', plaintext: '072D43A077075292', ciphertext: '7A8E7BFA937E89A3'},
        {key: '0170F175468FB5E6', plaintext: '0756D8E0774761D2', ciphertext: '432193B78951FC98'},
        {key: '3000000000000000', plaintext: '1000000000000001', ciphertext: '7D856F9A613063F2'},
        {key: '1111111111111111', plaintext: '1111111111111111', ciphertext: '2466DD878B963C9D'},
        {key: '0123456789ABCDEF', plaintext: '1111111111111111', ciphertext: '61F9C3802281B096'},
        {key: '37D06BB516CB7546', plaintext: '164D5E404F275232', ciphertext: '5F99D04F5B163969'},
        {key: '018310DC409B26D6', plaintext: '1D9D5C5018F728C2', ciphertext: 'D1ABB290658BC778'},
        {key: '04689104C2FD3B2F', plaintext: '26955F6835AF609A', ciphertext: 'D887E0393C2DA6E3'},
        {key: '1C587F1C13924FEF', plaintext: '305532286D6F295A', ciphertext: '55CB3774D13EF201'},
        {key: '07A7137045DA2A16', plaintext: '3BDD119049372802', ciphertext: '2EEDDA93FFD39C79'},
        {key: '04B915BA43FEB5B6', plaintext: '42FD443059577FA2', ciphertext: '353882B109CE8F1A'},
        {key: '49793EBC79B3258F', plaintext: '437540C8698F3CFA', ciphertext: '53C55F9CB49FC019'},
        {key: '025816164629B007', plaintext: '480D39006EE762F2', ciphertext: '7555AE39F59B87BD'},
        {key: '3849674C2602319E', plaintext: '51454B582DDF440A', ciphertext: 'A25E7856CF2651EB'},
        {key: '0131D9619DC1376E', plaintext: '5CD54CA83DEF57DA', ciphertext: 'B1B8CC0B250F09A0'},
        {key: '1F08260D1AC2465E', plaintext: '6B056E18759F5CCA', ciphertext: '4A057A3B24D3977B'},
        {key: '43297FAD38E373FE', plaintext: '762514B829BF486A', ciphertext: '13F04154D69D1AE5'},
        {key: '0000000000000000', plaintext: 'FFFFFFFFFFFFFFFF', ciphertext: '014933E0CDAFF6E4'},
        {key: 'FFFFFFFFFFFFFFFF', plaintext: 'FFFFFFFFFFFFFFFF', ciphertext: '51866FD5B85ECB8A'},
        {key: 'FEDCBA9876543210', plaintext: 'FFFFFFFFFFFFFFFF', ciphertext: '6B5C5A9C5D9E0A5A'},
        {key: '57686F206973204A6F686E2047616C743F', plaintext: 'FEDCBA9876543210', ciphertext: 'CC91732B8022F684'},
        {key: '6162636465666768696A6B6C6D6E6F707172737475767778797A', plaintext: '424C4F5746495348', ciphertext: '324ED0FEF413A203'},
        {key: 'F0F0F0F0F0F0F0F0', plaintext: 'FEDCBA9876543210', ciphertext: 'F9AD597C49DB005E'},
        {key: 'F0E1F0E1F0E1F0E1', plaintext: 'FEDCBA9876543210', ciphertext: 'E91D21C1D961A6D6'},
        {key: 'F0E1D2F0E1D2F0E1D2', plaintext: 'FEDCBA9876543210', ciphertext: 'E9C2B70A1BC65CF3'},
        {key: 'F0E1D2C3F0E1D2C3', plaintext: 'FEDCBA9876543210', ciphertext: 'BE1E639408640F05'},
        {key: 'F0E1D2C3B4F0E1D2C3B4', plaintext: 'FEDCBA9876543210', ciphertext: 'B39E44481BDB1E6E'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Blowfish();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex'))
                .toBe(ciphertext.toLowerCase());
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Blowfish();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex'))
                .toBe(plaintext.toLowerCase());
        });
    });
});
