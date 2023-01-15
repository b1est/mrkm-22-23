#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include "settings.hpp"
int main()
{
    RSA	*r = RSA_new();
    BIGNUM *bne = BN_new();
    unsigned long	e = RSA_F4;
    BN_set_word(bne,e);
    char from[CRYPTO_RSA_KEY_LEN] = {MESSAGE};
    char to[CRYPTO_RSA_KEY_LEN] = {0};

    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // генерація відкритого і закритого ключа
        RSA_generate_key_ex(r, CRYPTO_RSA_KEY_LEN, bne, NULL);

        // шифрування повідомлення
        RSA_public_encrypt(
            strlen(from), 
            (unsigned char *)from, 
            (unsigned char *)to, 
            r, 
            RSA_PKCS1_OAEP_PADDING
        );

        // розшифрування повідомлення
        RSA_private_decrypt(
            RSA_size(r), 
            (unsigned char *)to, 
            (unsigned char *)from, 
            r, 
            RSA_PKCS1_OAEP_PADDING
        );
    }

    return 0;
}