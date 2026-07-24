
#ifndef CRYPTIAN_ALGORITM_BLOCK_H_
#define CRYPTIAN_ALGORITM_BLOCK_H_

#include "algorithm-base.h"

namespace cryptian {

namespace algorithm {

class AlgorithmBlock: public AlgorithmBase {

public:
    virtual std::size_t getBlockSize() = 0;

    // The raw encrypt and decrypt entry points are a single block primitive.
    // Anything longer belongs in a mode, which slices the input and calls this
    // once per block. Accepting more here means silently dropping or zeroing
    // whatever does not fit, so it is rejected instead.
    bool isDataSizeValid(std::size_t size) {
        return size == getBlockSize();
    }

};

};

};

#endif