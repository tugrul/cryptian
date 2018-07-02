
#include "ofb.h"
#include <cmath>

namespace cryptian {

namespace mode {

namespace ofb {

bool Ofb::isPaddingRequired() {
    return false;
}

std::vector<char> Cipher::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();

    std::vector<char> blocks(chunk.size());

    for (size_t i = 0 ; i < chunk.size(); i++) {

        std::vector<char> cipher = _algorithm->encrypt(_register);

        blocks[i] = chunk[i] ^ cipher[0];

        std::copy(_register.begin() + 1, _register.end(), _register.begin());
        _register[blockSize - 1] = cipher[0];

    }

    return blocks;
}


std::vector<char> Decipher::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();

    std::vector<char> blocks(chunk.size());

    for (size_t i = 0 ; i < chunk.size(); i++) {

        std::vector<char> cipher = _algorithm->encrypt(_register);

        std::copy(_register.begin() + 1, _register.end(), _register.begin());
        _register[blockSize - 1] = cipher[0];

        blocks[i] = chunk[i] ^ cipher[0];

    }

    return blocks;

}

};

};

};