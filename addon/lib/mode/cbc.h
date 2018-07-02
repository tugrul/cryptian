
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace cbc {

class Cbc : public cryptian::mode::ModeBase {
public:
    bool isPaddingRequired();
};


class Cipher : public Cbc {
public:
    std::vector<char> transform(const std::vector<char>);

};

class Decipher: public Cbc {
public:
    std::vector<char> transform(const std::vector<char>);
};

};

};

};
