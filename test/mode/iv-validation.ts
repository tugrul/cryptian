
import {expect} from '@jest/globals';

import {default as cryptian, ModeList} from '../..';

const {algorithm, mode} = cryptian;

// An undersized initialization vector used to be accepted silently. The mode
// register is indexed up to the algorithm block size while transforming, so a
// short vector caused reads and writes past the end of the allocation.
describe('initialization vector validation', () => {

    const ivModes: Array<ModeList> = [
        ModeList.Cbc,
        ModeList.Pcbc,
        ModeList.Cfb,
        ModeList.Ncfb,
        ModeList.Ofb,
        ModeList.Nofb,
        ModeList.Ctr
    ];

    const createAlgorithm = () => {
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(Buffer.alloc(16, 0x01));
        return rijndael;
    };

    ivModes.forEach(name => {

        describe(name + ' mode', () => {

            it('rejects an iv shorter than the block size', () => {

                expect(() => {
                    new mode[name].Cipher(createAlgorithm(), Buffer.alloc(4, 0));
                }).toThrow(/Iv size/);

                expect(() => {
                    new mode[name].Decipher(createAlgorithm(), Buffer.alloc(4, 0));
                }).toThrow(/Iv size/);
            });

            it('rejects an iv longer than the block size', () => {

                expect(() => {
                    new mode[name].Cipher(createAlgorithm(), Buffer.alloc(32, 0));
                }).toThrow(/Iv size/);
            });

            it('rejects an empty iv', () => {

                expect(() => {
                    new mode[name].Cipher(createAlgorithm(), Buffer.alloc(0));
                }).toThrow(/Iv size/);
            });

            it('accepts an iv matching the block size', () => {

                expect(() => {
                    new mode[name].Cipher(createAlgorithm(), Buffer.alloc(16, 0));
                }).not.toThrow();
            });
        });

    });

    describe('ecb mode', () => {

        it('accepts an empty iv because it keeps no register', () => {

            expect(() => {
                new mode.ecb.Cipher(createAlgorithm(), Buffer.alloc(0));
            }).not.toThrow();
        });

        it('rejects a partial iv', () => {

            expect(() => {
                new mode.ecb.Cipher(createAlgorithm(), Buffer.alloc(4, 0));
            }).toThrow(/Iv size/);
        });
    });

    describe('block size other than 16 bytes', () => {

        it('validates against the algorithm block size, not a fixed width', () => {

            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(Buffer.alloc(16, 0x01));

            expect(blowfish.getBlockSize()).toBe(8);

            expect(() => {
                new mode.cbc.Cipher(blowfish, Buffer.alloc(16, 0));
            }).toThrow(/Iv size/);

            expect(() => {
                new mode.cbc.Cipher(blowfish, Buffer.alloc(8, 0));
            }).not.toThrow();
        });
    });

});
