#pragma once
#include "ElGamal.h"
#include <openssl/bn.h>
#include <string>

class Wrapper {
private:
    El_Gamal* el_gamal_ctx;
public:
    Wrapper();
    ~Wrapper();

    int generate_private_key(BN_ULONG bits_p = 1024, BN_ULONG bits_g = 512);

    int generate_public_key();

    El_Gamal_ciphertext* encrypt(std::string msg);

    std::string decrypt(El_Gamal_ciphertext* ciphertext);

    El_Gamal_signature* sign(std::string msg);

    bool verify(std::string msg, El_Gamal_signature* signature);

    int del_private_key();

    int del_public_key();

    static int free_ciphertext(El_Gamal_ciphertext* ciphertext);

    static int free_signature(El_Gamal_signature* signature);

};
