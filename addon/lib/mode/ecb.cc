
#include "ecb.h"
#include <cmath>

namespace cryptian {

namespace mode {

namespace ecb {

bool Ecb::isPaddingRequired() {
    return true;
}

std::vector<char> Ecb::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);

    std::vector<char> blocks(blockSize * blocksCount);


    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        std::vector<char> cipher = process(std::vector<char>(chunk.begin() + offset, chunk.begin() + offset + blockSize));
        std::copy(cipher.begin(), cipher.end(), blocks.begin() + offset);


    }

    return blocks;
}



};

};

};