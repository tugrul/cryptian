
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace pcbc {

class Pcbc : public cryptian::mode::ModeBase {
public:
    bool isPaddingRequired();
};


class Cipher : public Pcbc {
public:
    std::vector<char> transform(const std::vector<char>);

};

class Decipher: public Pcbc {
public:
    std::vector<char> transform(const std::vector<char>);
};

};

};

};
