
#include "ncfb.h"
#include <cmath>

namespace cryptian {

namespace mode {

namespace ncfb {

bool Ncfb::isPaddingRequired() {
    return false;
}

std::vector<char> Cipher::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();

    std::vector<char> blocks(chunk.size());
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);


    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        if (registerPos == 0) {
            cipher = _algorithm->encrypt(_register);

            for (size_t j = 0; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ cipher[j];
            }

            std::copy_n(blocks.begin() + offset, blockSize, _register.begin());
        } else {

            size_t size = blockSize - registerPos;

            for (size_t j = 0; j < size; j++) {
                blocks[offset + j] = chunk[offset + j] ^ cipher[registerPos + j];
            }

            std::copy_n(blocks.begin() + offset, size, _register.begin() + registerPos);

            cipher = _algorithm->encrypt(_register);

            for (size_t j = size; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ cipher[j - size];
            }

            std::copy_n(blocks.begin() + offset + size, registerPos, _register.begin());
        }


    }

    size_t modSize = chunk.size() % blockSize;

    if (modSize == 0) {
        return blocks;
    }

    size_t offset = blocksCount * blockSize;


    if (registerPos == 0) {

        registerPos = modSize;

        cipher = _algorithm->encrypt(_register);

        for (size_t j = 0; j < modSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ cipher[j];
        }

        std::copy_n(blocks.begin() + offset, modSize, _register.begin());

    } else {

        size_t size = blockSize - registerPos;
        size_t minSize = size < modSize ? size : modSize;

        for (size_t j = 0; j < minSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ cipher[j + registerPos];
        }

        std::copy_n(blocks.begin() + offset, minSize, _register.begin() + registerPos);

        registerPos += minSize;

        if (minSize >= modSize) {
            return blocks;
        }

        cipher = _algorithm->encrypt(_register);

        offset += minSize;

        registerPos = modSize - minSize;

        for (size_t j = 0; j < registerPos; j++) {
            blocks[offset + j] = chunk[offset + j] ^ _register[j];
        }

        std::copy_n(blocks.begin() + offset, registerPos, _register.begin());
    }

    return blocks;
}


std::vector<char> Decipher::transform(const std::vector<char> chunk) {

    const std::size_t blockSize = _algorithm->getBlockSize();

    std::vector<char> blocks(chunk.size());
    const std::size_t blocksCount = std::floor(chunk.size() / blockSize);


    for (size_t i = 0 ; i < blocksCount; i++) {

        size_t offset = i * blockSize;

        if (registerPos == 0) {

            cipher = _algorithm->encrypt(_register);

            std::copy_n(chunk.begin() + offset, blockSize, _register.begin());

            for (size_t j = 0; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ cipher[j];
            }

        } else {

            size_t size = blockSize - registerPos;

            for (size_t j = 0; j < size; j++) {
                blocks[offset + j] = chunk[offset + j] ^ cipher[registerPos + j];
            }

            std::copy_n(chunk.begin() + offset, size, _register.begin() + registerPos);

            cipher = _algorithm->encrypt(_register);

            std::copy_n(chunk.begin() + offset + size, registerPos, _register.begin());

            for (size_t j = size; j < blockSize; j++) {
                blocks[offset + j] = chunk[offset + j] ^ cipher[j - size];
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

        cipher = _algorithm->encrypt(_register);

        std::copy_n(chunk.begin() + offset, modSize, _register.begin());

        for (size_t j = 0; j < modSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ cipher[j];
        }


    } else {

        size_t size = blockSize - registerPos;
        size_t minSize = size < modSize ? size : modSize;

        for (size_t j = 0; j < minSize; j++) {
            blocks[offset + j] = chunk[offset + j] ^ cipher[j + registerPos];
        }

        std::copy_n(chunk.begin() + offset, minSize, _register.begin() + registerPos);

        registerPos += minSize;

        if (minSize >= modSize) {
            return blocks;
        }

        cipher = _algorithm->encrypt(_register);

        std::copy_n(chunk.begin() + offset, registerPos, _register.begin());

        offset += minSize;

        registerPos = modSize - minSize;

        for (size_t j = 0; j < registerPos; j++) {
            blocks[offset + j] = chunk[offset + j] ^ cipher[j];
        }



    }


    return blocks;

}

};

};

};