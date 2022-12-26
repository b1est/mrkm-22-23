#pragma once
#include "CryptoAPI.h"
#include "ElGamal.h"
#include <openssl/bn.h>
#include <string>

Wrapper::Wrapper() {
    this->el_gamal_ctx = ElGamal_init();
}

Wrapper::~Wrapper() {
    ElGamal_free(this->el_gamal_ctx);
}

int Wrapper::generate_private_key(BN_ULONG bits_p, BN_ULONG bits_g) {
    return ElGamal_generate_private_key(this->el_gamal_ctx, bits_p, bits_g);
}

int Wrapper::generate_public_key() {
    return ElGamal_generate_public_key(this->el_gamal_ctx);
}

int Wrapper::del_private_key() {
    return ElGamal_free_priv(this->el_gamal_ctx);
}

int Wrapper::del_public_key() {
    return ElGamal_free_pub(this->el_gamal_ctx);
}

El_Gamal_ciphertext* Wrapper::encrypt(std::string msg) {
    El_Gamal_ciphertext* ciphertext = NULL;
    if (ElGamal_encrypt(this->el_gamal_ctx, msg, ciphertext) != SUCCESS)
        return NULL;
    return ciphertext;
}

std::string Wrapper::decrypt(El_Gamal_ciphertext* ciphertext) {
    std::string decrypted_msg;
    decrypted_msg.clear();
    if (ElGamal_decrypt(this->el_gamal_ctx, decrypted_msg, ciphertext) != SUCCESS)
        return "";
    return decrypted_msg;
}

El_Gamal_signature* Wrapper::sign(std::string msg) {
    El_Gamal_signature* signature = NULL;
    if (ElGamal_sign(this->el_gamal_ctx, msg, signature) != SUCCESS)
        return NULL;
    return signature;
}

bool Wrapper::verify(std::string msg, El_Gamal_signature* signature) {
    if (ElGamal_verify(this->el_gamal_ctx, msg, signature) == SUCCESS)
        return true;
    else
        return false;
}

int Wrapper::free_ciphertext(El_Gamal_ciphertext* ciphertext) {
    return ElGamal_ciphertext_free(ciphertext);
}

int Wrapper::free_signature(El_Gamal_signature* signature) {
    return ElGamal_signature_free(signature);
}
