

const {padding} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

describe('pkcs7', () => {

    it('should be constructor', () => {
        assert(typeof padding.Pkcs7 === 'function', 'there is no Pkcs5 constructor');
    });

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
            padded: 'f5ec378f5c625e1b782bff8301c7cbe510101010101010101010101010101010'}
    ];

    it('should done padding operation', () => {

        fixture.forEach(sample => {

            describe('blocksize ' + sample.blockSize + ' pad ' + sample.size + ' bytes', () => {

                const padder = new padding.Pkcs7(sample.blockSize);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(padded.equals(padder.pad(unpadded)));
            });

        });

    });


    it('should done unpadding operation', () => {

        fixture.forEach(sample => {

            describe('blocksize ' + sample.blockSize + ' unpad ' + sample.size + ' bytes', () => {

                const padder = new padding.Pkcs7(sample.blockSize);
                const padded = new Buffer(sample.padded, 'hex');
                const unpadded = new Buffer(sample.unpadded, 'hex');

                assert(unpadded.equals(padder.unpad(padded)));
            });

        });

    });


});

