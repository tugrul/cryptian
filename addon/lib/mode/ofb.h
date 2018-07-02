
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace ofb {

class Ofb : public cryptian::mode::ModeBase  {
public:
    bool isPaddingRequired();
};

class Cipher : public Ofb {
public:
    std::vector<char> transform(const std::vector<char>);

};

class Decipher: public Ofb {
public:
    std::vector<char> transform(const std::vector<char>);
};

};

};

};
