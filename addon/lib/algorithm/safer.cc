
#include "safer.h"

namespace cryptian {

namespace algorithm {

Safer::Safer() {

    unsigned int exp_val = 1;

	for (size_t i = 0; i < TAB_LEN; i++) {

		exp_tab[i] = (unsigned char) (exp_val & 0xFF);
		log_tab[exp_tab[i]] = (unsigned char) i;

		exp_val = exp_val * 45 % 257;

	}

}

std::string Safer::getName() {
    return "SAFER";
}

std::size_t Safer::getVersion() {
    return 20010801;
}

std::size_t Safer::getBlockSize() {
    return 8;
}

std::vector<std::size_t> Safer::getKeySizes() {
    return {8, 16};
}


std::vector<char> Safer::encrypt(const std::vector<char> plaintext) {

    unsigned char t;
    unsigned int rnd;
    unsigned char *key = local_key;

    unsigned char ciphertext[8];

    std::fill_n(ciphertext, 8, 0);
    std::copy_n(plaintext.begin(), plaintext.size() > 8 ? 8 : plaintext.size(), ciphertext);


    if (SAFER_MAX_NOF_ROUNDS < (rnd = *key)) {
        rnd = SAFER_MAX_NOF_ROUNDS;
    }

    while (rnd--) {
        ciphertext[0] ^= *++key;
        ciphertext[1] += *++key;
        ciphertext[2] += *++key;
        ciphertext[3] ^= *++key;
        ciphertext[4] ^= *++key;
        ciphertext[5] += *++key;
        ciphertext[6] += *++key;
        ciphertext[7] ^= *++key;

        ciphertext[0] = exp_tab[ciphertext[0] & 0xFF] + *++key;
        ciphertext[1] = log_tab[ciphertext[1] & 0xFF] ^ *++key;
        ciphertext[2] = log_tab[ciphertext[2] & 0xFF] ^ *++key;
        ciphertext[3] = exp_tab[ciphertext[3] & 0xFF] + *++key;
        ciphertext[4] = exp_tab[ciphertext[4] & 0xFF] + *++key;
        ciphertext[5] = log_tab[ciphertext[5] & 0xFF] ^ *++key;
        ciphertext[6] = log_tab[ciphertext[6] & 0xFF] ^ *++key;
        ciphertext[7] = exp_tab[ciphertext[7] & 0xFF] + *++key;

        pht(ciphertext[0], ciphertext[1]);
        pht(ciphertext[2], ciphertext[3]);
        pht(ciphertext[4], ciphertext[5]);
        pht(ciphertext[6], ciphertext[7]);

        pht(ciphertext[0], ciphertext[2]);
        pht(ciphertext[4], ciphertext[6]);
        pht(ciphertext[1], ciphertext[3]);
        pht(ciphertext[5], ciphertext[7]);
        pht(ciphertext[0], ciphertext[4]);
        pht(ciphertext[1], ciphertext[5]);
        pht(ciphertext[2], ciphertext[6]);
        pht(ciphertext[3], ciphertext[7]);

        t = ciphertext[1];
        ciphertext[1] = ciphertext[4];
        ciphertext[4] = ciphertext[2];
        ciphertext[2] = t;

        t = ciphertext[3];
        ciphertext[3] = ciphertext[5];
        ciphertext[5] = ciphertext[6];
        ciphertext[6] = t;

    }

    ciphertext[0] ^= *++key;
    ciphertext[1] += *++key;
    ciphertext[2] += *++key;
    ciphertext[3] ^= *++key;
    ciphertext[4] ^= *++key;
    ciphertext[5] += *++key;
    ciphertext[6] += *++key;
    ciphertext[7] ^= *++key;

    return std::vector<char>(ciphertext, ciphertext + 8);
}

std::vector<char> Safer::decrypt(const std::vector<char> ciphertext) {

    unsigned char t;
    unsigned int rnd;
    unsigned char *key = local_key;

    unsigned char plaintext[8];

    std::fill_n(plaintext, 8, 0);
    std::copy_n(ciphertext.begin(), ciphertext.size() > 8 ? 8 : ciphertext.size(), plaintext);


    if (SAFER_MAX_NOF_ROUNDS < (rnd = *key)) {
        rnd = SAFER_MAX_NOF_ROUNDS;
    }

    key += SAFER_BLOCK_LEN * (1 + 2 * rnd);

    plaintext[7] ^= *key;
    plaintext[6] -= *--key;
    plaintext[5] -= *--key;
    plaintext[4] ^= *--key;
    plaintext[3] ^= *--key;
    plaintext[2] -= *--key;
    plaintext[1] -= *--key;
    plaintext[0] ^= *--key;

    while (rnd--) {

        t = plaintext[4];
        plaintext[4] = plaintext[1];
        plaintext[1] = plaintext[2];
        plaintext[2] = t;

        t = plaintext[5];
        plaintext[5] = plaintext[3];
        plaintext[3] = plaintext[6];
        plaintext[6] = t;

        ipht(plaintext[0], plaintext[4]);
        ipht(plaintext[1], plaintext[5]);
        ipht(plaintext[2], plaintext[6]);
        ipht(plaintext[3], plaintext[7]);

        ipht(plaintext[0], plaintext[2]);
        ipht(plaintext[4], plaintext[6]);
        ipht(plaintext[1], plaintext[3]);
        ipht(plaintext[5], plaintext[7]);

        ipht(plaintext[0], plaintext[1]);
        ipht(plaintext[2], plaintext[3]);
        ipht(plaintext[4], plaintext[5]);
        ipht(plaintext[6], plaintext[7]);

        plaintext[7] -= *--key;
        plaintext[6] ^= *--key;
        plaintext[5] ^= *--key;
        plaintext[4] -= *--key;
        plaintext[3] -= *--key;
        plaintext[2] ^= *--key;
        plaintext[1] ^= *--key;
        plaintext[0] -= *--key;

        plaintext[7] = log_tab[plaintext[7] & 0xFF] ^ *--key;
        plaintext[6] = exp_tab[plaintext[6] & 0xFF] - *--key;
        plaintext[5] = exp_tab[plaintext[5] & 0xFF] - *--key;
        plaintext[4] = log_tab[plaintext[4] & 0xFF] ^ *--key;
        plaintext[3] = log_tab[plaintext[3] & 0xFF] ^ *--key;
        plaintext[2] = exp_tab[plaintext[2] & 0xFF] - *--key;
        plaintext[1] = exp_tab[plaintext[1] & 0xFF] - *--key;
        plaintext[0] = log_tab[plaintext[0] & 0xFF] ^ *--key;
    }

    return std::vector<char>(plaintext, plaintext + 8);

}

void Safer::reset() {



	unsigned int j;
	unsigned char ka[SAFER_BLOCK_LEN + 1];
	unsigned char kb[SAFER_BLOCK_LEN + 1];
    unsigned char *key = local_key;
    unsigned char key_buffer[16];

    std::fill_n(local_key, 217, 0);
    std::fill_n(key_buffer, 16, 0);

    std::copy_n(_key.begin(), _key.size() > 16 ? 16 : _key.size(), key_buffer);

    strengthened = 1;
    nofRounds = 8;

	if (SAFER_MAX_NOF_ROUNDS < nofRounds) {
        nofRounds = SAFER_MAX_NOF_ROUNDS;
    }

    *key++ = (unsigned char) nofRounds;

	ka[SAFER_BLOCK_LEN] = 0;
	kb[SAFER_BLOCK_LEN] = 0;

	for (j = 0; j < SAFER_BLOCK_LEN; j++) {
		ka[SAFER_BLOCK_LEN] ^= ka[j] = rotl8(key_buffer[j], 5);
		kb[SAFER_BLOCK_LEN] ^= kb[j] = *key++ = key_buffer[_key.size() > 8 ? j + 8 : j];
	}

	for (size_t i = 1; i <= nofRounds; i++) {

		for (size_t j = 0; j < SAFER_BLOCK_LEN + 1; j++) {
			ka[j] = rotl8(ka[j], 6);
			kb[j] = rotl8(kb[j], 6);
		}

		for (size_t j = 0; j < SAFER_BLOCK_LEN; j++) {

			if (strengthened) {
                *key++ =
				    (ka[(j + 2 * i - 1) %
				      (SAFER_BLOCK_LEN + 1)] +
				     exp_tab[exp_tab[18 * i + j + 1]]) &
				    0xFF;
            } else {
                *key++ =
				    (ka[j] +
				     exp_tab[exp_tab[18 * i + j + 1]]) &
				    0xFF;
            }

        }

		for (size_t j = 0; j < SAFER_BLOCK_LEN; j++) {

			if (strengthened) {
                *key++ =
				    (kb
				     [(j + 2 * i) %
				      (SAFER_BLOCK_LEN + 1)] +
				     exp_tab[exp_tab[18 * i + j + 10]]) &
				    0xFF;
            } else {
                *key++ =
				    (kb[j] +
				     exp_tab[exp_tab[18 * i + j + 10]]) &
				    0xFF;
            }

        }
	}

	for (j = 0; j < SAFER_BLOCK_LEN + 1; j++) {
        ka[j] = kb[j] = 0;
    }


}

};

};