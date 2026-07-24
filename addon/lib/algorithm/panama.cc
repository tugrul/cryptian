
#include "panama.h"

namespace cryptian {

namespace algorithm {

namespace {

inline unsigned int rotl(unsigned int x, unsigned int n) {
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
}

}  // namespace

std::string Panama::getName() {
    return "panama";
}

std::size_t Panama::getVersion() {
    return 1;
}

std::size_t Panama::getIvSize() {
    return 32;
}

std::vector<std::size_t> Panama::getKeySizes() {
    return std::vector<std::size_t>{32};
}

void Panama::resetState() {

    _tap = 0;

    for (std::size_t stage = 0; stage < PANAMA_STAGES; stage++) {

        for (std::size_t word = 0; word < PANAMA_STAGE_SIZE; word++) {
            _buffer[stage][word] = 0;
        }
    }

    for (std::size_t i = 0; i < PANAMA_STATE_SIZE; i++) {
        _state[i] = 0;
    }
}

// The three state transformations, written as loops rather than the seventeen
// way unrolled macros of the reference code. gamma is the non-linear step, pi
// disperses bits by rotating word 7i into position i by a triangular amount,
// and theta diffuses each word with two of its neighbours.
void Panama::rho(unsigned int* theta) {

    unsigned int gamma[PANAMA_STATE_SIZE];
    unsigned int pi[PANAMA_STATE_SIZE];

    for (std::size_t i = 0; i < PANAMA_STATE_SIZE; i++) {
        gamma[i] = _state[i] ^ (_state[(i + 1) % PANAMA_STATE_SIZE] | ~_state[(i + 2) % PANAMA_STATE_SIZE]);
    }

    pi[0] = gamma[0];

    for (std::size_t i = 1; i < PANAMA_STATE_SIZE; i++) {
        pi[i] = rotl(gamma[(7 * i) % PANAMA_STATE_SIZE],
                     static_cast<unsigned int>((i * (i + 1) / 2) % 32));
    }

    for (std::size_t i = 0; i < PANAMA_STATE_SIZE; i++) {
        theta[i] = pi[i]
                 ^ pi[(i + 1) % PANAMA_STATE_SIZE]
                 ^ pi[(i + 4) % PANAMA_STATE_SIZE];
    }
}

void Panama::push(const unsigned int* input, std::size_t blocks) {

    for (std::size_t block = 0; block < blocks; block++) {

        unsigned int theta[PANAMA_STATE_SIZE];

        rho(theta);

        const unsigned int* injected = input + block * PANAMA_STAGE_SIZE;

        // Tap 16 is taken before the tap moves, so sigma sees its old position.
        unsigned int* tap16 = _buffer[(_tap + 16) & (PANAMA_STAGES - 1)];

        _tap = (_tap - 1) & (PANAMA_STAGES - 1);

        unsigned int* tap0 = _buffer[_tap];
        unsigned int* tap25 = _buffer[(_tap + 25) & (PANAMA_STAGES - 1)];

        // lambda. Tap 25 is finished before tap 0 changes, which is why the
        // reference code needs no temporary for the feedback path.
        for (std::size_t i = 0; i < PANAMA_STAGE_SIZE; i++) {
            tap25[i] ^= tap0[(i + 2) & (PANAMA_STAGE_SIZE - 1)];
        }

        for (std::size_t i = 0; i < PANAMA_STAGE_SIZE; i++) {
            tap0[i] = injected[i] ^ tap0[i];
        }

        // sigma. On a push the injected block takes the place that tap 4
        // occupies on a pull.
        _state[0] = theta[0] ^ 0x00000001;

        for (std::size_t i = 1; i <= 8; i++) {
            _state[i] = theta[i] ^ injected[i - 1];
        }

        for (std::size_t i = 9; i <= 16; i++) {
            _state[i] = theta[i] ^ tap16[i - 9];
        }
    }
}

void Panama::pull(unsigned int* output, std::size_t blocks) {

    for (std::size_t block = 0; block < blocks; block++) {

        // The output of a pull is the top half of the state as it stands at
        // the start of the round, before any of the transformations run.
        if (output != nullptr) {

            for (std::size_t i = 0; i < PANAMA_STAGE_SIZE; i++) {
                output[block * PANAMA_STAGE_SIZE + i] = _state[9 + i];
            }
        }

        unsigned int theta[PANAMA_STATE_SIZE];

        rho(theta);

        unsigned int* tap4 = _buffer[(_tap + 4) & (PANAMA_STAGES - 1)];
        unsigned int* tap16 = _buffer[(_tap + 16) & (PANAMA_STAGES - 1)];

        // The state words used by lambda below are the ones from the start of
        // the round, because sigma does not write the state until afterwards.
        unsigned int previous[PANAMA_STAGE_SIZE];

        for (std::size_t i = 0; i < PANAMA_STAGE_SIZE; i++) {
            previous[i] = _state[i + 1];
        }

        _tap = (_tap - 1) & (PANAMA_STAGES - 1);

        unsigned int* tap0 = _buffer[_tap];
        unsigned int* tap25 = _buffer[(_tap + 25) & (PANAMA_STAGES - 1)];

        for (std::size_t i = 0; i < PANAMA_STAGE_SIZE; i++) {
            tap25[i] ^= tap0[(i + 2) & (PANAMA_STAGE_SIZE - 1)];
        }

        for (std::size_t i = 0; i < PANAMA_STAGE_SIZE; i++) {
            tap0[i] = previous[i] ^ tap0[i];
        }

        _state[0] = theta[0] ^ 0x00000001;

        for (std::size_t i = 1; i <= 8; i++) {
            _state[i] = theta[i] ^ tap4[i - 1];
        }

        for (std::size_t i = 9; i <= 16; i++) {
            _state[i] = theta[i] ^ tap16[i - 9];
        }
    }
}

void Panama::reset() {

    resetState();

    // The key and the vector are pushed in as whole 256 bit blocks; anything
    // that does not fill one is not pushed, which is what libmcrypt does.
    unsigned int words[16];

    std::size_t keyBlocks = _key.size() / (PANAMA_STAGE_SIZE * 4);

    for (std::size_t i = 0; i < keyBlocks * PANAMA_STAGE_SIZE; i++) {
        words[i] = load(_key.data() + i * 4);
    }

    push(words, keyBlocks);

    std::size_t ivBlocks = _iv.size() / (PANAMA_STAGE_SIZE * 4);

    for (std::size_t i = 0; i < ivBlocks * PANAMA_STAGE_SIZE; i++) {
        words[i] = load(_iv.data() + i * 4);
    }

    if (ivBlocks > 0) {
        push(words, ivBlocks);
    }

    // Thirty two blank pulls separate the loading from the output, then one
    // more produces the first block of key material.
    pull(nullptr, 32);
    pull(_keyMaterial, 1);

    _keyMaterialPosition = 0;
}

std::vector<char> Panama::crypt(const std::vector<char> input) {

    std::vector<char> output(input.size());

    for (std::size_t i = 0; i < input.size(); i++) {

        if (_keyMaterialPosition == PANAMA_STAGE_SIZE * 4) {
            pull(_keyMaterial, 1);
            _keyMaterialPosition = 0;
        }

        // The key material is consumed as bytes of the pulled words, least
        // significant first.
        unsigned int word = _keyMaterial[_keyMaterialPosition / 4];
        unsigned char byte = static_cast<unsigned char>((word >> (8 * (_keyMaterialPosition % 4))) & 0xFF);

        output[i] = static_cast<char>(static_cast<unsigned char>(input[i]) ^ byte);

        _keyMaterialPosition++;
    }

    return output;
}

std::vector<char> Panama::encrypt(const std::vector<char> plaintext) {
    return crypt(plaintext);
}

std::vector<char> Panama::decrypt(const std::vector<char> ciphertext) {
    return crypt(ciphertext);
}

};

};
