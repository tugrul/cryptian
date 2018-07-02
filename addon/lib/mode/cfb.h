
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace cfb {


class Cfb: public cryptian::mode::ModeBase {
public:
    bool isPaddingRequired();
};

class Cipher : public Cfb {
public:
    std::vector<char> transform(const std::vector<char>);

};

class Decipher: public Cfb {
public:
    std::vector<char> transform(const std::vector<char>);
};

};

};

};
