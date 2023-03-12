

import bindings from 'bindings';

import type { AlgorithmBlock } from './algorithm/block';
import type { AlgorithmStream } from './algorithm/stream';
import type { Mode } from './mode';

export type ModeCipherDecipher = {
    Cipher: typeof Mode,
    Decipher: typeof Mode
}

export enum ModeList {
    Cbc = 'cbc',
    Pcbc = 'pcbc',
    Cfb = 'cfb',
    Ctr = 'ctr',
    Ecb = 'ecb',
    Ncfb = 'ncfb',
    Nofb = 'nofb',
    Ofb = 'ofb'
}

export enum BlockAlgorithmList {
    Blowfish = 'Blowfish',
    Cast128 = 'Cast128',
    Cast256 = 'Cast256',
    Des = 'Des',
    Threeway = 'Threeway',
    Gost = 'Gost',
    Loki97 = 'Loki97',
    Rc2 = 'Rc2',
    Rijndael128 = 'Rijndael128',
    Rijndael192 = 'Rijndael192',
    Rijndael256 = 'Rijndael256',
    Safer = 'Safer',
    Saferplus = 'Saferplus',
    Tripledes = 'Tripledes',
    Xtea = 'Xtea',
    Dummy = 'Dummy'
}

export enum StreamAlgorithmList {
    Arcfour = 'Arcfour',
    Enigma = 'Enigma',
    Wake = 'Wake'
}

export enum PaddingList {
    Null = 'Null',
    Pkcs5 = 'Pkcs5',
    Pkcs7 = 'Pkcs7',
    Space = 'Space',
    Iso7816 = 'Iso7816',
    Iso10126 = 'Iso10126',
    AnsiX923 = 'AnsiX923'
}

type AlgoList = {
    [Property in `${BlockAlgorithmList}`]: typeof AlgorithmBlock
} & {
    [Property in `${StreamAlgorithmList}`]: typeof AlgorithmStream
};


export type Cryptian = {
    Mode: typeof Mode,
    AlgorithmBlock: typeof AlgorithmBlock,
    AlgorithmStream: typeof AlgorithmStream,
    mode: {
        [Property in `${ModeList}`]: ModeCipherDecipher
    },
    algorithm: AlgoList
};

const cryptian = bindings('cryptian') as Cryptian;

export default cryptian as Cryptian;

import Null from "./padding/null";
import Pkcs5 from "./padding/pkcs5";
import Pkcs7 from "./padding/pkcs7";
import Space from "./padding/space";
import Iso7816 from "./padding/iso-7816";
import Iso10126 from "./padding/iso-10126";
import AnsiX923 from "./padding/ansi-x923";

export const padding = {
    Null, Pkcs5, Pkcs7, Space, Iso7816, Iso10126, AnsiX923
}

import { BlockEncrypt, BlockDecrypt } from './transform/block';
import { StreamEncrypt, StreamDecrypt } from './transform/stream';


import { prepareStream } from './stream';


export const createDecryptStream = prepareStream(cryptian, StreamDecrypt, BlockDecrypt);

export const createEncryptStream = prepareStream(cryptian, StreamEncrypt, BlockEncrypt);



