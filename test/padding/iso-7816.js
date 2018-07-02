

const {padding} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('iso-7816', () => {

    it('should be constructor', () => {
        assert(typeof padding.Iso7816 === 'function', 'there is no Null constructor');
    });



    const fixture = [
        {size: 1, unpadded: 'd1',               padded: 'd180000000000000'},
        {size: 2, unpadded: '7c7b',             padded: '7c7b800000000000'},
        {size: 3, unpadded: '304c5a',           padded: '304c5a8000000000'},
        {size: 4, unpadded: '116b5452',         padded: '116b545280000000'},
        {size: 5, unpadded: '0575ba559d',       padded: '0575ba559d800000'},
        {size: 6, unpadded: '6433efaf7a4e',     padded: '6433efaf7a4e8000'},
        {size: 7, unpadded: '416fe992c737bc',   padded: '416fe992c737bc80'},
        {size: 8, unpadded: 'd91f5fd905527480', padded: 'd91f5fd9055274808000000000000000'}
    ];

    it('should done padding operation', () => {

        fixture.forEach(sample => {

            describe('pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Iso7816(8);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

    });


    it('should done unpadding operation', () => {

        fixture.forEach(sample => {

            describe('unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Iso7816(8);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

