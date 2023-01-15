#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <chrono>
#include "settings.hpp"

int main()
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey  publicKey;

    std::string message = "hello";
    auto m = CryptoPP::Integer((const byte *)message.data(), message.size());

    CryptoPP::Integer c;
    CryptoPP::Integer r;

    std::chrono::time_point<clock_tt> m_beg;

    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // генерування закритого ключа
        privateKey.GenerateRandomWithKeySize(rng, CRYPTO_RSA_KEY_LEN);
    }
    std::cout << "pritate key: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;

    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // генерування відкритого ключа по закритому ключу
        publicKey.Initialize(privateKey.GetModulus(), privateKey.GetPublicExponent());
    }
    std::cout << "open key: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;



    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // шифрування
        c = publicKey.ApplyFunction(m);  
    }
    std::cout << "ciphertext: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;
    

    m_beg = clock_tt::now();
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // розшифрування
        r = privateKey.CalculateInverse(rng, c);  
    }
    std::cout << "plaintext: " << std::chrono::duration_cast<second_t>(clock_tt::now() - m_beg).count() << std::endl;
}

// req = r.MinEncodedSize();
// recovered.resize(req);
// r.Encode((byte *)recovered.data(), recovered.size());
