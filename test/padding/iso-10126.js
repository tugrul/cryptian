

const {padding} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('iso-10126', () => {

    it('should be constructor', () => {
        assert(typeof padding.Iso10126 === 'function', 'there is no Null constructor');
    });



    const fixture = [
        {size: 7, unpadded: 'd1',               padded: 'd19c6fa8024b6a07'},
        {size: 6, unpadded: '7c7b',             padded: '7c7bc1bb612aee06'},
        {size: 5, unpadded: '304c5a',           padded: '304c5a2b24444205'},
        {size: 4, unpadded: '116b5452',         padded: '116b545272741704'},
        {size: 3, unpadded: '0575ba559d',       padded: '0575ba559d0c4b03'},
        {size: 2, unpadded: '6433efaf7a4e',     padded: '6433efaf7a4e2402'},
        {size: 1, unpadded: '416fe992c737bc',   padded: '416fe992c737bc01'},
        {size: 8, unpadded: 'd91f5fd9055274ea', padded: 'd91f5fd9055274ea1ad227c97c515608'}
    ];

    it('should done padding operation', () => {

        fixture.forEach(sample => {

            describe('pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Iso10126(8);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                const target = padder.pad(unpadded);

                assert.equal(sample.size, target[target.length - 1]);
            });

        });

    });


    it('should done unpadding operation', () => {

        fixture.forEach(sample => {

            describe('unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Iso10126(8);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

