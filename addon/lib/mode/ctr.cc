
#include "ctr.h"
#include <cmath>

namespace cryptian {

namespace mode {

namespace ctr {

bool Ctr::isPaddingRequired() {
    return false;
}

void Ctr::increment() {
    size_t blockSize = _algorithm->getBlockSize();

    std::vector<unsigned char> counter(_register.begin(), _register.end());

    while (blockSize-- > 0) {
        if (counter[blockSize] == 0xFF) {
            counter[blockSize] = 0;
        } else {
            counter[blockSize]++;
            break;
        }
    }

    std::copy(counter.begin(), counter.end(), _register.begin());
}

std::vector<char> Ctr::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();

    std::vector<char> blocks(chunk.size());
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);

    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        if (counterPos == 0) {
            counter = _algorithm->encrypt(_register);

            for (size_t j = 0; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ counter[j];
            }

            increment();
        } else {

            size_t size = blockSize - counterPos;

            for (size_t j = 0; j < size; j++) {
                blocks[offset + j] = chunk[offset + j] ^ counter[counterPos + j];
            }

            increment();

            counter = _algorithm->encrypt(_register);

            for (size_t j = size; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ counter[j - size];
            }

        }

    }

    size_t modSize = chunk.size() % blockSize;

    if (modSize == 0) {
        return blocks;
    }

    size_t offset = blocksCount * blockSize;

    if (counterPos == 0) {
        counterPos = modSize;

        counter = _algorithm->encrypt(_register);

        for (size_t j = 0; j < modSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ counter[j];
        }

    } else {


        size_t size = blockSize - counterPos;
        size_t minSize = size < modSize ? size : modSize;

        for (size_t j = 0; j < minSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ counter[j + counterPos];
        }

        counterPos += minSize;

        if (minSize >= modSize) {
            return blocks;
        }

        increment();

        counter = _algorithm->encrypt(_register);

        offset += minSize;

        for (size_t j = 0; j < modSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ counter[j];
        }

        counterPos = modSize - minSize;

    }

    return blocks;
}



};

};

};