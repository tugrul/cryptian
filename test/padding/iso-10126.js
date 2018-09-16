

const {padding} = require('../..');
const assert = require('assert');

describe('iso-10126', () => {

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

    describe('padding', () => {

        fixture.forEach(sample => {

            it('should pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Iso10126(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                const target = padder.pad(unpadded);

                assert.equal(sample.size, target[target.length - 1]);
            });

        });

    });


    describe('unpadding', () => {

        fixture.forEach(sample => {

            it('should unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Iso10126(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

