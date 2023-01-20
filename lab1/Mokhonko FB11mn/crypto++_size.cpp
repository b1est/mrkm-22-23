#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include "settings.hpp"
int main()
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey  publicKey;

    std::string message = MESSAGE;
    auto m = CryptoPP::Integer((const byte *)message.data(), message.size());

    CryptoPP::Integer c;
    CryptoPP::Integer r;

    
    for (uint64_t i = 0; i < NUM_TESTS; i++) {
        // генерування ключів
        privateKey.GenerateRandomWithKeySize(rng, CRYPTO_RSA_KEY_LEN);
        publicKey.Initialize(privateKey.GetModulus(), privateKey.GetPublicExponent());

        // шифрування
        c = publicKey.ApplyFunction(m);

        // розшифрування
        r = privateKey.CalculateInverse(rng, c);
    }
      
}

// req = r.MinEncodedSize();
// recovered.resize(req);
// r.Encode((byte *)recovered.data(), recovered.size());
