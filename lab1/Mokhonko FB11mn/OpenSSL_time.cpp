#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <chrono>
#include "settings.hpp"
int main()
{
    RSA	*r = RSA_new();
    BIGNUM *bne = BN_new();
    unsigned long	e = RSA_F4;
    BN_set_word(bne,e);
    char from[CRYPTO_RSA_KEY_LEN] = {MESSAGE};
    char to[CRYPTO_RSA_KEY_LEN] = {0};

    std::chrono::time_point<clock_tt> m_beg;

    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // генерація відкритого і закритого ключа
        RSA_generate_key_ex(r, CRYPTO_RSA_KEY_LEN, bne, NULL);
    }
    std::cout << "private/open key: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;

    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // шифрування повідомлення
        RSA_public_encrypt(
            strlen(from), 
            (unsigned char *)from, 
            (unsigned char *)to, 
            r, 
            RSA_PKCS1_OAEP_PADDING
        );  
    }
    std::cout << "ciphertext: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;

    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // розшифрування повідомлення
        RSA_private_decrypt(
            RSA_size(r), 
            (unsigned char *)to, 
            (unsigned char *)from, 
            r, 
            RSA_PKCS1_OAEP_PADDING
        );  
    }
    std::cout << "plaintext: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;

    return 0;
}
