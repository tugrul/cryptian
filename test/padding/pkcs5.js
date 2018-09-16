

const {padding} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('pkcs5', () => {

    it('should not accept different padding size by 8', () => {

        assert.throws(() => {
            new padding.Pkcs5(16);
        }, Error, 'PKCS5 allows only 8 bytes block size');

    });

    const fixture = [
        {size: 1, unpadded: 'd1',               padded: 'd107070707070707'},
        {size: 2, unpadded: '7c7b',             padded: '7c7b060606060606'},
        {size: 3, unpadded: '304c5a',           padded: '304c5a0505050505'},
        {size: 4, unpadded: '116b5452',         padded: '116b545204040404'},
        {size: 5, unpadded: '0575ba559d',       padded: '0575ba559d030303'},
        {size: 6, unpadded: '6433efaf7a4e',     padded: '6433efaf7a4e0202'},
        {size: 7, unpadded: '416fe992c737bc',   padded: '416fe992c737bc01'},
        {size: 8, unpadded: 'd91f5fd905527408', padded: 'd91f5fd9055274080808080808080808'}
    ];

    describe('padding', () => {

        fixture.forEach(sample => {

            it('should pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Pkcs5(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

    });


    describe('unpadding', () => {

        fixture.forEach(sample => {

            it('should unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Pkcs5(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

