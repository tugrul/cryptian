

#ifndef CRYPTIAN_MODE_BASE_H_
#define CRYPTIAN_MODE_BASE_H_

#include <vector>
#include "algorithm-block.h"

namespace cryptian {

namespace mode {

class ModeBase {
protected:
    cryptian::algorithm::AlgorithmBlock* _algorithm;
    std::vector<char> _register;
public:

    void setAlgorithm(cryptian::algorithm::AlgorithmBlock* algorithm) {
        _algorithm = algorithm;
    }

    void setIv(const std::vector<char> iv) {
        _register = iv;
    }

    std::size_t getBlockSize() {
        return _algorithm->getBlockSize();
    }

    bool isSizeValid(size_t size) {

        const std::size_t blockSize = _algorithm->getBlockSize();

        if (size % blockSize == 0) {
            return true;
        }

        return false;
    }

    virtual std::vector<char> transform(const std::vector<char>) = 0;
    virtual bool isPaddingRequired() = 0;
};

};

};

#endif  // ~ CRYPTIAN_MODE_BASE_H_