

import assert from "assert";

import {padding} from '../..';

describe('space', () => {

    const fixture = [
        {size: 1, unpadded: 'd1',               padded: 'd120202020202020'},
        {size: 2, unpadded: '7c7b',             padded: '7c7b202020202020'},
        {size: 3, unpadded: '304c5a',           padded: '304c5a2020202020'},
        {size: 4, unpadded: '116b5452',         padded: '116b545220202020'},
        {size: 5, unpadded: '0575ba559d',       padded: '0575ba559d202020'},
        {size: 6, unpadded: '6433efaf7a4e',     padded: '6433efaf7a4e2020'},
        {size: 7, unpadded: '416fe992c737bc',   padded: '416fe992c737bc20'},
        {size: 8, unpadded: 'd91f5fd905527420', padded: 'd91f5fd9055274202020202020202020'}
    ];

    describe('padding', () => {

        fixture.forEach(sample => {

            it('should pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Space(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

    });


    describe('unpadding', () => {

        fixture.forEach(sample => {

            it('should unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Space(8);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

