

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
    virtual ~ModeBase() {}

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

    // Modes that keep a feedback/counter register need an initialization
    // vector exactly as wide as the algorithm block. ECB keeps no state
    // between blocks and overrides this to accept an empty vector.
    virtual bool isIvRequired() {
        return true;
    }

    // The register is indexed up to the block size while transforming, so an
    // undersized initialization vector would read and write past the end of
    // the allocation. Reject it before any transform can run.
    bool isIvValid(size_t size) {

        if (!isIvRequired() && size == 0) {
            return true;
        }

        return size == _algorithm->getBlockSize();
    }

    virtual std::vector<char> transform(const std::vector<char>) = 0;
    virtual bool isPaddingRequired() = 0;
};

};

};

#endif  // ~ CRYPTIAN_MODE_BASE_H_