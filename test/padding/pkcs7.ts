
import assert from "assert";

import {padding} from '../..';

describe('pkcs7', () => {

    const fixture = [
        {blockSize: 8, size: 1, unpadded: 'd1',               padded: 'd107070707070707'},
        {blockSize: 8, size: 2, unpadded: '7c7b',             padded: '7c7b060606060606'},
        {blockSize: 8, size: 3, unpadded: '304c5a',           padded: '304c5a0505050505'},
        {blockSize: 8, size: 4, unpadded: '116b5452',         padded: '116b545204040404'},
        {blockSize: 8, size: 5, unpadded: '0575ba559d',       padded: '0575ba559d030303'},
        {blockSize: 8, size: 6, unpadded: '6433efaf7a4e',     padded: '6433efaf7a4e0202'},
        {blockSize: 8, size: 7, unpadded: '416fe992c737bc',   padded: '416fe992c737bc01'},
        {blockSize: 8, size: 8, unpadded: 'd91f5fd905527408', padded: 'd91f5fd9055274080808080808080808'},
        {blockSize: 16, size: 12, unpadded: '25f7051f8c31e01ca8140ff6', padded: '25f7051f8c31e01ca8140ff604040404'},
        {blockSize: 16, size: 16, unpadded: 'f5ec378f5c625e1b782bff8301c7cbe5',
            padded: 'f5ec378f5c625e1b782bff8301c7cbe510101010101010101010101010101010'},
        {blockSize: 16, size: 18, unpadded: '03bc5901e2a8c02ae2b070855653cb1f400e', 
            padded: '03bc5901e2a8c02ae2b070855653cb1f400e0e0e0e0e0e0e0e0e0e0e0e0e0e0e'}
    ];

    describe('padding', () => {

        fixture.forEach(sample => {

            it('blocksize ' + sample.blockSize + ' pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Pkcs7(sample.blockSize);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

        it('should pad empty buffer of blockSize 8', () => {
            const padder = new padding.Pkcs7(8);
            const padded = padder.pad(Buffer.alloc(0))

            assert(padded.equals(Buffer.from('0808080808080808', 'hex')));
        });


        it('should pad empty buffer of blockSize 16', () => {
            const padder = new padding.Pkcs7(16);
            const padded = padder.pad(Buffer.alloc(0))

            assert(padded.equals(Buffer.from('10101010101010101010101010101010', 'hex')));
        });

    });


    describe('unpadding', () => {

        fixture.forEach(sample => {

            it('blocksize ' + sample.blockSize + ' unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Pkcs7(sample.blockSize);
                const padded = Buffer.from(sample.padded, 'hex');
                const unpadded = Buffer.from(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

        it('should unpad only padding data of blockSize 8', () => {

            const padder = new padding.Pkcs7(8);
            const unpadded = padder.unpad(Buffer.from('0808080808080808', 'hex'));

            assert(unpadded.length === 0);
        });

        it('should unpad only padding data of blockSize 16', () => {

            const padder = new padding.Pkcs7(16);
            const unpadded = padder.unpad(Buffer.from('10101010101010101010101010101010', 'hex'));

            assert(unpadded.length === 0);
        });

    });


});

