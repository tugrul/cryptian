
const Padding = require('./padding.js');

exports.prepareStream = function prepareStream(cryptian, Stream, Block) {
    
    return (cipher, Padder, options) => {
    
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

};


