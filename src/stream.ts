
import Padding from './padding';

import type { Cryptian } from '.';
import type { BlockDecrypt, BlockEncrypt } from './transform/block';
import type { StreamEncrypt, StreamDecrypt } from './transform/stream';

import type { Mode } from './mode';
import type { AlgorithmBlock } from './algorithm/block';
import type { AlgorithmStream } from './algorithm/stream';
import type { TransformOptions } from 'stream';


type StreamCons = typeof StreamDecrypt | typeof StreamEncrypt;
type BlockCons = typeof BlockDecrypt | typeof BlockEncrypt;

export function prepareStream(cryptian: Cryptian, Stream: StreamCons, Block: BlockCons) {


    return (cipher: Mode | AlgorithmBlock | AlgorithmStream, Padder?: typeof Padding, options?: TransformOptions) => {
    
        if (cipher instanceof cryptian.AlgorithmStream) {
            return new Stream(options, cipher);
        }

        if (!(cipher instanceof cryptian.Mode)) {
            
            if (cipher instanceof cryptian.AlgorithmBlock) {
                throw new Error('You should wrap block algorithm with mode algorithm');
            }
            
            
            throw new Error('Cipher should be algorithm for stream encryption or mode for block encryption');
        }
        
        if (!cipher.isPaddingRequired()) {
            return new Block(options, cipher);
        }
        
        if (typeof Padder !== 'function') {
            throw new Error('Padder should be constructor');
        }

        const padder = new Padder(cipher.getBlockSize());

        if (!(padder instanceof Padding)) {
            throw new Error('Padder constructor should be instance of Padding');
        }

        return new Block(options, cipher, padder);
    
    };

}


