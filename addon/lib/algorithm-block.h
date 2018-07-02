
#ifndef CRYPTIAN_ALGORITM_BLOCK_H_
#define CRYPTIAN_ALGORITM_BLOCK_H_

#include "algorithm-base.h"

namespace cryptian {

namespace algorithm {

class AlgorithmBlock: public AlgorithmBase {

public:
    virtual std::size_t getBlockSize() = 0;

};

};

};

#endif