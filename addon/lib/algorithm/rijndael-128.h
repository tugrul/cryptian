

#include "rijndael.h"

namespace cryptian {

namespace algorithm {

class Rijndael128 : public Rijndael {
public:
    Rijndael128() : Rijndael() {
        Nb = 4;
    }

    std::string getName() {
        return "Rijndael-128";
    }
};

};

};
