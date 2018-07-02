
#include "nofb.h"
#include <cmath>

namespace cryptian {

namespace mode {

namespace nofb {

bool Nofb::isPaddingRequired() {
    return false;
}

std::vector<char> Nofb::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();

    std::vector<char> blocks(chunk.size());
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);

    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        if (registerPos == 0) {

            _register = _algorithm->encrypt(_register);

            for (size_t j = 0; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ _register[j];
            }

        } else {

            size_t size = blockSize - registerPos;

            for (size_t j = 0; j < size; j++) {
                blocks[offset + j] = chunk[offset + j] ^ _register[registerPos + j];
            }

            _register = _algorithm->encrypt(_register);

            for (size_t j = size; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ _register[j - size];
            }

        }

    }

    size_t modSize = chunk.size() % blockSize;

    if (modSize == 0) {
        return blocks;
    }

    size_t offset = blocksCount * blockSize;

    if (registerPos == 0) {
        registerPos = modSize;

        _register = _algorithm->encrypt(_register);

        for (size_t j = 0; j < modSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ _register[j];
        }

    } else {

        size_t size = blockSize - registerPos;
        size_t minSize = size < modSize ? size : modSize;

        for (size_t j = 0; j < minSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ _register[j + registerPos];
        }

        registerPos += minSize;

        if (minSize >= modSize) {
            return blocks;
        }

        _register = _algorithm->encrypt(_register);

        for (size_t j = minSize; j < modSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ _register[j - minSize];
        }

        registerPos = modSize - minSize;

    }


    return blocks;
}



};

};

};