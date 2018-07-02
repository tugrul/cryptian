

const {padding} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('null', () => {

    it('should be constructor', () => {
        assert(typeof padding.Null === 'function', 'there is no Null constructor');
    });



    const fixture = [
        {size: 1, unpadded: 'd1',               padded: 'd100000000000000'},
        {size: 2, unpadded: '7c7b',             padded: '7c7b000000000000'},
        {size: 3, unpadded: '304c5a',           padded: '304c5a0000000000'},
        {size: 4, unpadded: '116b5452',         padded: '116b545200000000'},
        {size: 5, unpadded: '0575ba559d',       padded: '0575ba559d000000'},
        {size: 6, unpadded: '6433efaf7a4e',     padded: '6433efaf7a4e0000'},
        {size: 7, unpadded: '416fe992c737bc',   padded: '416fe992c737bc00'},
        {size: 8, unpadded: 'd91f5fd905527400', padded: 'd91f5fd9055274000000000000000000'}
    ];

    it('should done padding operation', () => {

        fixture.forEach(sample => {

            describe('pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Null(8);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

    });


    it('should done unpadding operation', () => {

        fixture.forEach(sample => {

            describe('unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Null(8);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

