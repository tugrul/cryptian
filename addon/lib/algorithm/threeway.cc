
#include "threeway.h"

namespace cryptian {

namespace algorithm {

std::string Threeway::getName() {
    return "3-WAY";
}

std::size_t Threeway::getVersion() {
    return 20010801;
}

std::size_t Threeway::getBlockSize() {
    return 12;
}

std::vector<std::size_t> Threeway::getKeySizes() {
    return {12};
}


void Threeway::reset() {

    key = {};
    std::copy_n(_key.begin(), 12, key.c);

    for (size_t i = 0; i < 3; i++) {
        key.ui[i] = byteswapBE(key.ui[i]);
    }

}

std::vector<char> Threeway::encrypt(const std::vector<char> plaintext) {

	unsigned int rcon[12];

    block ciphertext = {};

    std::copy_n(plaintext.begin(), 12, ciphertext.c);

    for (size_t i = 0; i < 3; i++) {
        ciphertext.ui[i] = byteswapBE(ciphertext.ui[i]);
    }

	rndcon_gen(STRT_E, rcon);

	for (size_t i = 0; i < NMBR; i++) {
        ciphertext.ui[0] ^= key.ui[0] ^ (rcon[i] << 16);
        ciphertext.ui[1] ^= key.ui[1];
        ciphertext.ui[2] ^= key.ui[2] ^ rcon[i];
        rho(ciphertext.ui);
	}

	ciphertext.ui[0] ^= key.ui[0] ^ (rcon[NMBR] << 16);
	ciphertext.ui[1] ^= key.ui[1];
	ciphertext.ui[2] ^= key.ui[2] ^ rcon[NMBR];

	theta(ciphertext.ui);

    for (size_t i = 0; i < 3; i++) {
        ciphertext.ui[i] = byteswapBE(ciphertext.ui[i]);
    }

    return std::vector<char>(ciphertext.c, ciphertext.c + 12);
}

std::vector<char> Threeway::decrypt(const std::vector<char> ciphertext) {

    unsigned int rcon[12]; // the `inverse' round constants

    block plaintext = {};
    block _key = {};

    std::copy_n(ciphertext.begin(), 12, plaintext.c);
    std::copy_n(key.c, 12, _key.c);

    for (size_t i = 0; i < 3; i++) {
        plaintext.ui[i] = byteswapBE(plaintext.ui[i]);
    }

	theta(_key.ui);
	mu(_key.ui);

	rndcon_gen(STRT_D, rcon);

	mu(plaintext.ui);

	for (size_t i = 0; i < NMBR; i++) {
		plaintext.ui[0] ^= _key.ui[0] ^ (rcon[i] << 16);
		plaintext.ui[1] ^= _key.ui[1];
		plaintext.ui[2] ^= _key.ui[2] ^ rcon[i];
		rho(plaintext.ui);
	}

	plaintext.ui[0] ^= _key.ui[0] ^ (rcon[NMBR] << 16);
	plaintext.ui[1] ^= _key.ui[1];
	plaintext.ui[2] ^= _key.ui[2] ^ rcon[NMBR];

	theta(plaintext.ui);
	mu(plaintext.ui);

    for (size_t i = 0; i < 3; i++) {
        plaintext.ui[i] = byteswapBE(plaintext.ui[i]);
    }

	return std::vector<char>(plaintext.c, plaintext.c + 12);
}


void Threeway::mu(unsigned int* a) {
    // inverts the order of the bits of a

    unsigned int b[3];

    b[0] = b[1] = b[2] = 0;

    for (size_t i = 0; i < 32; i++) {

        b[0] <<= 1;
        b[1] <<= 1;
        b[2] <<= 1;

        if (a[0] & 1) {
            b[2] |= 1;
        }


        if (a[1] & 1) {
            b[1] |= 1;
        }

        if (a[2] & 1) {
            b[0] |= 1;
        }

        a[0] >>= 1;
        a[1] >>= 1;
        a[2] >>= 1;
    }

    a[0] = b[0];
    a[1] = b[1];
    a[2] = b[2];
}

void Threeway::gamma(unsigned int* a) {
    // the nonlinear step

	unsigned int b[3];

	b[0] = a[0] ^ (a[1] | (~a[2]));
	b[1] = a[1] ^ (a[2] | (~a[0]));
	b[2] = a[2] ^ (a[0] | (~a[1]));

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}


void Threeway::theta(unsigned int* a) {
    // the linear step

	unsigned int b[3];

	b[0] =
	    a[0] ^ (a[0] >> 16) ^ (a[1] << 16) ^ (a[1] >> 16) ^ (a[2] <<
								 16) ^
	    (a[1] >> 24) ^ (a[2] << 8) ^ (a[2] >> 8) ^ (a[0] << 24) ^ (a[2]
								       >>
								       16)
	    ^ (a[0] << 16) ^ (a[2] >> 24) ^ (a[0] << 8);
	b[1] =
	    a[1] ^ (a[1] >> 16) ^ (a[2] << 16) ^ (a[2] >> 16) ^ (a[0] <<
								 16) ^
	    (a[2] >> 24) ^ (a[0] << 8) ^ (a[0] >> 8) ^ (a[1] << 24) ^ (a[0]
								       >>
								       16)
	    ^ (a[1] << 16) ^ (a[0] >> 24) ^ (a[1] << 8);
	b[2] =
	    a[2] ^ (a[2] >> 16) ^ (a[0] << 16) ^ (a[0] >> 16) ^ (a[1] <<
								 16) ^
	    (a[0] >> 24) ^ (a[1] << 8) ^ (a[1] >> 8) ^ (a[2] << 24) ^ (a[1]
								       >>
								       16)
	    ^ (a[2] << 16) ^ (a[1] >> 24) ^ (a[2] << 8);

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}

void Threeway::pi_1(unsigned int* a) {
	a[0] = (a[0] >> 10) ^ (a[0] << 22);
	a[2] = (a[2] << 1) ^ (a[2] >> 31);
}

void Threeway::pi_2(unsigned int* a) {
	a[0] = (a[0] << 1) ^ (a[0] >> 31);
	a[2] = (a[2] >> 10) ^ (a[2] << 22);
}

void Threeway::rho(unsigned int* a) {
    // the round function

	theta(a);
	pi_1(a);
	gamma(a);
	pi_2(a);
}

void Threeway::rndcon_gen(unsigned int strt, unsigned int* rtab) {
    // generates the round constants

	for (size_t i = 0; i <= NMBR; i++) {

		rtab[i] = strt;
		strt <<= 1;

		if (strt & 0x10000) {
			strt ^= 0x11011;
        }
	}
}

};

};

