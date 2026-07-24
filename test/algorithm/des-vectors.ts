
import {expect} from '@jest/globals';

import {default as cryptian} from '../..';

const {algorithm} = cryptian;

// Published single DES vectors.
// Taken from published test data rather than produced by this implementation,
// so they check the cipher against its specification and not against itself.
describe('des published vectors', () => {

    const vectors = [
        {key: '0113B970FD34F2CE', plaintext: '059B5E0851CF143A', ciphertext: '86A560F10EC6D85B'},
        {key: '04689104C2FD3B2F', plaintext: '26955F6835AF609A', ciphertext: '5C513C9C4886C088'},
        {key: '1C587F1C13924FEF', plaintext: '305532286D6F295A', ciphertext: '63FAC0D034D9F793'},
        {key: '3CDE816EF9EF8EDB', plaintext: '68FF9D6068C71513', ciphertext: '84595F5B9D046132'},
        {key: '584023641ABA6176', plaintext: '004BD6EF09176062', ciphertext: '88BF0DB6D70DEE56'},
        {key: '9AB645E268430854', plaintext: 'F45E6819E3108559', ciphertext: 'F0C76BA556283B2F'},
        {key: 'C6F974504D954C7E', plaintext: 'D6C059A85EE2B13E', ciphertext: '25977533635BEB5B'},
        {key: 'EBBBBAEBFBBEFABA', plaintext: '37DFE527086AF0A0', ciphertext: '5F53C6C87760256E'},
        {key: 'D5D44FF720683D0D', plaintext: '0100000000000000', ciphertext: '6F353E3388ABE2EF'},
        {key: '0801010101010101', plaintext: '0000000000000000', ciphertext: '809F5F873C1FD761'},
        {key: '0110010101010101', plaintext: '0000000000000000', ciphertext: 'DFDD3CC64DAE1642'},
        {key: '0101200101010101', plaintext: '0000000000000000', ciphertext: '90BA680B22AEB525'},
        {key: '0101014001010101', plaintext: '0000000000000000', ciphertext: 'C22F0A294A71F29F'},
        {key: '0101010180010101', plaintext: '0000000000000000', ciphertext: '19D032E64AB0BD8B'},
        {key: '0101010102010101', plaintext: '0000000000000000', ciphertext: '5570530829705592'},
        {key: '0101010101040101', plaintext: '0000000000000000', ciphertext: 'AE13DBD561488933'},
        {key: '0101010101010801', plaintext: '0000000000000000', ciphertext: 'DA99DBBC9A03F379'},
        {key: '0101010101010110', plaintext: '0000000000000000', ciphertext: '0875041E64C570F7'},
        {key: '10071034C8980120', plaintext: '0000000000000000', ciphertext: '83BC8EF3A6570183'},
        {key: '3107915498080101', plaintext: '0000000000000000', ciphertext: '7CFD82A593252B4E'},
        {key: '9107D01589190101', plaintext: '0000000000000000', ciphertext: '9592CB4110430787'},
        {key: '19079210981A0101', plaintext: '0000000000000000', ciphertext: 'AA85E74643233199'},
        {key: '1004801598190102', plaintext: '0000000000000000', ciphertext: '537AC95BE69DA1E1'},
        {key: '7CA110454A1A6E57', plaintext: '01A1D6D039776742', ciphertext: '690F5B0D9A26939B'},
        {key: '0170F175468FB5E6', plaintext: '0756D8E0774761D2', ciphertext: '0CD3DA020021DC09'},
        {key: '584023641ABA6176', plaintext: '004BD6EF09176062', ciphertext: '88BF0DB6D70DEE56'},
        {key: '1C587F1C13924FEF', plaintext: '305532286D6F295A', ciphertext: '63FAC0D034D9F793'},
        {key: '1086911519580101', plaintext: '0000000000000000', ciphertext: 'AF527120C485CBB0'},
        {key: '3107911598080140', plaintext: '0000000000000000', ciphertext: '406A9A6AB43399AE'},
        {key: '0107910491190401', plaintext: '0000000000000000', ciphertext: '2DFA9F4573594965'},
        {key: '1007921098190101', plaintext: '0000000000000000', ciphertext: 'D812D961F017D320'},
        {key: '1002911598190104', plaintext: '0000000000000000', ciphertext: '61C79C71921A2EF8'},
        {key: 'AB28E5763F23361A', plaintext: '3E33A822C3C3573A', ciphertext: '91481544C1349FD2'},
        {key: '9998A725FB90FDE4', plaintext: '8D3D08E33FBB298D', ciphertext: 'CF132CE973D16AA3'},
        {key: 'B4FCAFFB540653E5', plaintext: '334A69684C8B728A', ciphertext: '6717F2AD848DEAF7'},
        {key: 'D75198DF25CC1345', plaintext: '42AA788D751F49A5', ciphertext: '5302E3BA833E598A'},
        {key: 'E772317D24F6D307', plaintext: 'F5F17039BA37C1C0', ciphertext: '3D6A8E5991C3AEBB'},
        {key: '60D82E111EEEDEA8', plaintext: '2311E3818223DFA9', ciphertext: '17A4E5989E9C9A3D'},
        {key: 'FE80AB20EAC7AD16', plaintext: '841DEAE87A860986', ciphertext: '799A5A58E5CE9D59'},
        {key: '32F4E03E3B10DB42', plaintext: 'E296E275356AA9A0', ciphertext: 'B3963851F7DEB2C3'},
    ];

    vectors.forEach(({key, plaintext, ciphertext}, index) => {

        it('encrypts vector ' + index, () => {

            const cipher = new algorithm.Des();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.encrypt(Buffer.from(plaintext, 'hex')).toString('hex'))
                .toBe(ciphertext.toLowerCase());
        });

        it('decrypts vector ' + index, () => {

            const cipher = new algorithm.Des();
            cipher.setKey(Buffer.from(key, 'hex'));

            expect(cipher.decrypt(Buffer.from(ciphertext, 'hex')).toString('hex'))
                .toBe(plaintext.toLowerCase());
        });
    });
});
