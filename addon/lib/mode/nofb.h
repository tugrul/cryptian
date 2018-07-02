
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace nofb {

class Nofb : public cryptian::mode::ModeBase {
protected:
    size_t registerPos = 0;
public:
    std::vector<char> transform(const std::vector<char>);
    bool isPaddingRequired();
};


class Cipher : public Nofb {
};

class Decipher : public Nofb {
};

};

};

};
