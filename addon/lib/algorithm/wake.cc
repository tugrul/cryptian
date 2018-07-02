
#include "wake.h"

namespace cryptian {

namespace algorithm {


std::string Wake::getName() {
    return "WAKE";
}

std::size_t Wake::getVersion() {
    return 20010801;
}

std::size_t Wake::getIvSize() {
    return 32;
}

std::vector<std::size_t> Wake::getKeySizes() {
    return {32};
}

std::vector<char> Wake::encrypt(const std::vector<char> plaintext) {

    if (plaintext.size() == 0) {
        return std::vector<char>();
    }

    std::vector<char> ciphertext = plaintext;

    if (started == 0) {
        started = 1;
        encrypt(_iv);
    }

    for (size_t i = 0; i < ciphertext.size(); i++) {
        // R1 = V[n] = V[n] XOR R6 - here we do it per byte --sloooow
        // R1 is ignored
        ciphertext[i] ^= key.uc[16 + counter];

        // R2 = V[n] = R1 - per byte also
        key.uc[counter] = ciphertext[i];

        if (++counter == 4) {	// r6 was used - update it!
            counter = 0;

            key.ui[0] = byteswapBE(key.ui[0]);
            key.ui[4] = byteswapBE(key.ui[4]);

            M(1, 0);
            M(2, 1);
            M(3, 2);
            M(4, 3);

            key.ui[4] = byteswapBE(key.ui[4]);

        }
    }


    return ciphertext;
}

std::vector<char> Wake::decrypt(const std::vector<char> ciphertext) {


    if (ciphertext.size() == 0) {
        return std::vector<char>();
    }

    std::vector<char> plaintext = ciphertext;

	if (started == 0) {
		started = 1;

        key_block backup = key;

		std::vector<char> iv = encrypt(_iv);

        for (size_t i = 1; i < 5; i++) {
            key.ui[i] = backup.ui[i];
        }

		decrypt(iv);
	}


	for (size_t i = 0; i < plaintext.size(); i++) {
		// R1 = V[n]
		key.uc[counter] = plaintext[i];

		// R2 = V[n] = V[n] ^ R6
		// R2 is ignored
		plaintext[i] ^= key.uc[16 + counter];

		if (++counter == 4) {
			counter = 0;

            key.ui[0] = byteswapBE(key.ui[0]);
            key.ui[4] = byteswapBE(key.ui[4]);

			M(1, 0);
			M(2, 1);
			M(3, 2);
			M(4, 3);

            key.ui[4] = byteswapBE(key.ui[4]);
		}
	}

	return plaintext;

}

void Wake::reset() {

    unsigned int x, z;

	if (_key.size() != 32) {
        return;
    }

    std::copy_n(_key.begin(), _key.size() > 32 ? 32 : _key.size(), key.c + 4);

    for (size_t i = 1; i < 5; i++) {
        key.ui[i] = byteswapBE(key.ui[i]);
    }

    std::fill_n(t, 257, 0);

    std::copy_n(key.ui + 1, 4, t);

	for (size_t p = 4; p < 256; p++) {
		x = t[p - 4] + t[p - 1];
		t[p] = x >> 3 ^ tt[x & 7];
	}

	for (size_t p = 0; p < 23; p++)
		t[p] += t[p + 89];

	x = t[33];
	z = t[59] | 0x01000001;
	z &= 0xff7fffff;

	for (size_t p = 0; p < 256; p++) {
		x = (x & 0xff7fffff) + z;
		t[p] = (t[p] & 0x00ffffff) ^ x;
	}

	t[256] = t[0];
	x &= 0xff;

	for (size_t p = 0; p < 256; p++) {
		t[p] = t[x = (t[p ^ x] ^ x) & 0xff];
		t[x] = t[p + 1];
	}

	counter = 0;

    key.ui[3] = byteswapBE(key.ui[3]);

    if (_iv.size() > 0) {
        started = 0;
    } else {
        started = 1;
    }



}

const unsigned int Wake::tt[10] = {
	0x726a8f3bUL,
	0xe69a3b5cUL,
	0xd3c71fe5UL,
	0xab3c73d2UL,
	0x4d3a8eb3UL,
	0x0396d6e8UL,
	0x3d4c2f7aUL,
	0x9ee27cf3UL
};


};

};