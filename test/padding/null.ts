

import assert from "assert";

import {padding} from '../..';

describe('null', () => {

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

    describe('padding', () => {

        fixture.forEach(sample => {

            it('should pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Null(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

        it('should pad empty buffer', () => {
            const padder = new padding.Null(8);
            const padded = padder.pad(Buffer.alloc(0))

            assert(padded.equals(Buffer.from('0000000000000000', 'hex')));
        });

    });


    describe('unpadding', () => {

        fixture.forEach(sample => {

            it('should unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Null(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

        it('should unpad only padding data', () => {

            const padder = new padding.Null(8);
            const unpadded = padder.unpad(Buffer.from('0000000000000000', 'hex'));

            assert(unpadded.length === 0);
        });

    });


});

