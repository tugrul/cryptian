
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace ctr {

class Ctr : public cryptian::mode::ModeBase {
protected:
    std::vector<char> counter;
    size_t counterPos = 0;
    void increment();
public:
    std::vector<char> transform(const std::vector<char>);
    bool isPaddingRequired();
};


class Cipher : public Ctr {
};

class Decipher : public Ctr {
};

};

};

};
