
#include "dummy.h"

namespace cryptian {

namespace algorithm {

std::string Dummy::getName() {
    return "Dummy";
}

std::size_t Dummy::getVersion() {
    return 20180627;
}

std::size_t Dummy::getBlockSize() {
    return 8;
}

std::vector<std::size_t> Dummy::getKeySizes() {
    return {8};
}

std::vector<char> Dummy::encrypt(const std::vector<char> plaintext) {

	return plaintext;

}

std::vector<char> Dummy::decrypt(const std::vector<char> ciphertext) {

    return ciphertext;

}

};

};

