
import {expect} from '@jest/globals';

import {default as cryptian, padding, createEncryptStream, createDecryptStream, ModeList} from '../..';

import streamBuffers from 'stream-buffers';

const {algorithm, mode} = cryptian;

// The transform streams buffer whatever does not fill a block and carry it into
// the next chunk, so the boundaries between chunks are where this can go wrong.
// The chunk pattern must not change the result.
describe('stream chunk boundaries', () => {

    const padded: Array<ModeList> = [ModeList.Cbc, ModeList.Pcbc, ModeList.Ecb];
    const unpadded: Array<ModeList> = [ModeList.Cfb, ModeList.Ncfb, ModeList.Ofb, ModeList.Nofb, ModeList.Ctr];

    const patterns: Array<[string, (size: number) => Array<Buffer>]> = [
        ['a single chunk', size => [Buffer.alloc(size, 0x41)]],
        ['one byte at a time', size => Array.from({length: size}, () => Buffer.from([0x41]))],
        ['growing chunks', size => {
            const chunks: Array<Buffer> = [];
            let offset = 0;
            let width = 1;
            while (offset < size) {
                chunks.push(Buffer.alloc(Math.min(width, size - offset), 0x41));
                offset += width;
                width++;
            }
            return chunks;
        }],
        ['chunks one larger than a block', size => {
            const chunks: Array<Buffer> = [];
            for (let offset = 0; offset < size; offset += 17) {
                chunks.push(Buffer.alloc(Math.min(17, size - offset), 0x41));
            }
            return chunks;
        }],
        ['empty chunks interleaved', size => {
            const chunks: Array<Buffer> = [];
            for (let offset = 0; offset < size; offset += 5) {
                chunks.push(Buffer.alloc(0));
                chunks.push(Buffer.alloc(Math.min(5, size - offset), 0x41));
            }
            return chunks;
        }]
    ];

    const sizes = [1, 15, 16, 17, 48, 100];

    const roundTrip = (name: ModeList, chunks: Array<Buffer>, Padder?: typeof padding.Pkcs7) =>
        new Promise<Buffer>((resolve, reject) => {

            const key = Buffer.alloc(16, 0x07);
            const iv = name === ModeList.Ecb ? Buffer.alloc(0) : Buffer.alloc(16, 0x09);

            const build = () => {
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                return rijndael;
            };

            const encrypt = createEncryptStream(new mode[name].Cipher(build(), iv), Padder);
            const decrypt = encrypt.pipe(createDecryptStream(new mode[name].Decipher(build(), iv), Padder));
            const sink = decrypt.pipe(new streamBuffers.WritableStreamBuffer());

            sink.on('finish', () => {
                const contents = sink.getContents();
                resolve(contents === false ? Buffer.alloc(0) : contents);
            });

            encrypt.on('error', reject);
            decrypt.on('error', reject);
            sink.on('error', reject);

            chunks.forEach(chunk => encrypt.write(chunk));
            encrypt.end();
        });

    const check = (name: ModeList, Padder?: typeof padding.Pkcs7) => {

        describe(name, () => {

            patterns.forEach(([label, build]) => {

                it('round trips with ' + label, async () => {

                    for (const size of sizes) {

                        const recovered = await roundTrip(name, build(size), Padder);

                        expect(recovered.length).toBe(size);
                        expect(recovered.equals(Buffer.alloc(size, 0x41))).toBe(true);
                    }
                });
            });
        });
    };

    padded.forEach(name => check(name, padding.Pkcs7));
    unpadded.forEach(name => check(name));
});
