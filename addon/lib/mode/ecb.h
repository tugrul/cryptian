
#include <mode-base.h>

namespace cryptian {

namespace mode {

namespace ecb {

class Ecb : public cryptian::mode::ModeBase {
protected:
    virtual std::vector<char> process(std::vector<char>) = 0;
public:
    std::vector<char> transform(const std::vector<char>);
    bool isPaddingRequired();
};


class Cipher : public Ecb {
protected:
    std::vector<char> process(std::vector<char> chunk) {
        return _algorithm->encrypt(chunk);
    }
};

class Decipher : public Ecb {
protected:
    std::vector<char> process(std::vector<char> chunk) {
        return _algorithm->decrypt(chunk);
    }
};

};

};

};
