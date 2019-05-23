
#ifndef CRYPTIAN_ALGORITM_STREAM_H_
#define CRYPTIAN_ALGORITM_STREAM_H_

#include "algorithm-base.h"

namespace cryptian {

namespace algorithm {

class AlgorithmStream : public AlgorithmBase {
protected:
    std::vector<char> _iv;
public:
    virtual std::size_t getIvSize() = 0;

    void setIv(const std::vector<char> iv) {

        if (_iv.size() != iv.size() || std::equal(iv.begin(), iv.end(), _iv.begin())) {
            _iv = iv;
            reset();
        }

    }
};

};

};

#endif
