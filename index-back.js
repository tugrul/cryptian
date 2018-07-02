

const cryptian = module.exports = require('bindings')('cryptian');

const padding = cryptian.padding = {
    Null:  require('./lib/padding/null.js'),
    Pkcs5: require('./lib/padding/pkcs5.js'),
    Pkcs7: require('./lib/padding/pkcs7.js'),
    Space:  require('./lib/padding/space.js'),
    Iso7816: require('./lib/padding/iso-7816.js'),
    Iso10126: require('./lib/padding/iso-10126.js'),
    AnsiX923: require('./lib/padding/ansi-x923.js')
};


