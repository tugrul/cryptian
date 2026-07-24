
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

        // Mirrors setKey: rebuild only when the vector actually changed. The
        // negation was missing here, which inverted the test. Setting a
        // different vector of the same length fell through without storing it
        // or rebuilding, so the new vector was silently discarded and the
        // cipher kept running on the previous one, while setting the same
        // vector twice rebuilt for no reason.
        //
        // The size comparison must stay first for the same reason as in
        // setKey: this std::equal overload takes no end iterator for the
        // second range and would otherwise read past the end of _iv.
        if (_iv.size() != iv.size() || !std::equal(iv.begin(), iv.end(), _iv.begin())) {
            _iv = iv;
            reset();
        }

    }
};

};

};

#endif
