
#include "cbc.h"
#include <cmath>

namespace cryptian {

namespace mode {

namespace cbc {

bool Cbc::isPaddingRequired() {
    return true;
}

std::vector<char> Cipher::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);

    std::vector<char> blocks(blockSize * blocksCount);

    char* block = new char[blockSize]();

    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        std::copy_n(chunk.begin() + offset, blockSize, block);

        for (size_t j = 0; j < blockSize; j++) {
            block[j] ^= _register[j];
        }

        std::vector<char> cipher = _algorithm->encrypt(std::vector<char>(block, block + blockSize));

        std::copy(cipher.begin(), cipher.end(), blocks.begin() + offset);
        std::copy(cipher.begin(), cipher.end(), _register.begin());

    }

    delete[] block;

    return blocks;
}


std::vector<char> Decipher::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);

    std::vector<char> blocks(blockSize * blocksCount);

    char* block = new char[blockSize]();

    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        std::copy_n(chunk.begin() + offset, blockSize, block);

        std::vector<char> cipher = _algorithm->decrypt(std::vector<char>(block, block + blockSize));

        for (size_t j = 0; j < blockSize; j++) {
            cipher[j] ^= _register[j];
        }

        std::copy(cipher.begin(), cipher.end(), blocks.begin() + offset);
        std::copy(block, block + blockSize, _register.begin());

    }

    delete[] block;

    return blocks;

}

};

};

};