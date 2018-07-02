

#include "rijndael.h"

namespace cryptian {

namespace algorithm {

class Rijndael256 : public Rijndael {
public:
    Rijndael256() : Rijndael() {
        Nb = 8;
    }

    std::string getName() {
        return "Rijndael-256";
    }
};

};

};
