

#include "rijndael.h"

namespace cryptian {

namespace algorithm {

class Rijndael192 : public Rijndael {
public:
    Rijndael192() : Rijndael() {
        Nb = 6;
    }

    std::string getName() {
        return "Rijndael-192";
    }
};

};

};
