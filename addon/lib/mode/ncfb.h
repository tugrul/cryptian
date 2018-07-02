
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace ncfb {

class Ncfb : public cryptian::mode::ModeBase {
protected:
    size_t registerPos = 0;
    std::vector<char> cipher;
public:
    bool isPaddingRequired();
};

class Cipher : public Ncfb {
public:
    std::vector<char> transform(const std::vector<char>);

};

class Decipher: public Ncfb {
public:
    std::vector<char> transform(const std::vector<char>);
};

};

};

};
