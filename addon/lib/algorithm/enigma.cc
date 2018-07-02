
#include "enigma.h"

namespace cryptian {

namespace algorithm {


std::string Enigma::getName() {
    return "enigma";
}

std::size_t Enigma::getVersion() {
    return 20010801;
}

std::size_t Enigma::getIvSize() {
    return 0;
}

std::vector<std::size_t> Enigma::getKeySizes() {
    return {13};
}

std::vector<char> Enigma::encrypt(const std::vector<char> plaintext) {

    int i;
	int secureflg = 0;

    std::vector<char> ciphertext = plaintext;

	for (size_t j = 0; j < ciphertext.size(); j++) {

		i = ciphertext[j];

		if (secureflg) {
			nr1 = deck[n1] & MASK;
			nr2 = deck[nr1] & MASK;
		} else {
			nr1 = n1;
		}

		i = t2[(t3[(t1[(i + nr1) & MASK] + nr2) & MASK] - nr2) & MASK] - nr1;

		ciphertext[j] = i;

		n1++;

		if (n1 == ROTORSZ) {
			n1 = 0;
			n2++;
			if (n2 == ROTORSZ)
				n2 = 0;
			if (secureflg) {
				shuffle();
			} else {
				nr2 = n2;
			}
		}
	}

    return ciphertext;
}

std::vector<char> Enigma::decrypt(const std::vector<char> ciphertext) {

    int i;
    int secureflg = 0;

    std::vector<char> plaintext = ciphertext;


    for (size_t j = 0; j < plaintext.size(); j++) {

        i = plaintext[j];

        if (secureflg) {
            nr1 = deck[n1] & MASK;
            nr2 = deck[nr1] & MASK;
        } else {
            nr1 = n1;
        }

        i = t2[(t3[(t1[(i + nr1) & MASK] + nr2) & MASK] - nr2) & MASK] - nr1;

        plaintext[j] = i;

        n1++;

        if (n1 == ROTORSZ) {
            n1 = 0;
            n2++;
            if (n2 == ROTORSZ)
                n2 = 0;
            if (secureflg) {
                shuffle();
            } else {
                nr2 = n2;
            }
        }
    }

    return plaintext;
}

void Enigma::reset() {

    int ic, i, k, temp;
	unsigned random;
	int seed;

    std::fill(t1, t1 + 256, (char) 0);
    std::fill(t2, t2 + 256, (char) 0);
    std::fill(t3, t3 + 256, (char) 0);
    std::fill(deck, deck + 256, (char) 0);
    std::fill(cbuf, cbuf + 13, (char) 0);

	n1 = n2 = nr1 = nr2 = 0;

    std::copy_n(_key.begin(), _key.size() > 13 ? 13 : _key.size(), cbuf);

	seed = 123;
	for (i = 0; i < 13; i++)
		seed = seed * cbuf[i] + i;
	for (i = 0; i < ROTORSZ; i++) {
		t1[i] = i;
		deck[i] = i;
	}
	for (i = 0; i < ROTORSZ; i++) {
		seed = 5 * seed + cbuf[i % 13];
		random = seed % 65521;
		k = ROTORSZ - 1 - i;
		ic = (random & MASK) % (k + 1);
		random >>= 8;

		temp = t1[k];
		t1[k] = t1[ic];
		t1[ic] = temp;
		if (t3[k] != 0)
			continue;

		ic = (random & MASK) % k;
		while (t3[ic] != 0)
			ic = (ic + 1) % k;
		t3[k] = ic;
		t3[ic] = k;
	}

	for (i = 0; i < ROTORSZ; i++)
		t2[t1[i] & MASK] = i;


}


void Enigma::shuffle() {

	int i, ic, k, temp;
	unsigned random;
	static int seed = 123;

	for (i = 0; i < ROTORSZ; i++) {
		seed = 5 * seed + cbuf[i % 13];
		random = seed % 65521;
		k = ROTORSZ - 1 - i;
		ic = (random & MASK) % (k + 1);
		temp = deck[k];
		deck[k] = deck[ic];
		deck[ic] = temp;
	}

}

};

};