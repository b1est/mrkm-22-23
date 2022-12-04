#pragma once

#include <iostream>;
#include <random>;
#include <memory>;
#include <string>;

#include "cryptlib.h";
#include "modes.h";
#include "files.h";
#include "osrng.h";
#include "hex.h";
#include "rijndael.h";
#include "sha3.h";
#include "dsa.h";

using namespace CryptoPP;

void cryptoppAESEncrypt(const unsigned char* plainText, const unsigned char* plainKey, const unsigned char* salt);

void cryptoppSHA3(const unsigned char* plainText);

std::pair<CryptoPP::DSA::PublicKey, CryptoPP::DSA::PrivateKey> cryptoppDSAGenerateKey(unsigned int keyLength, AutoSeededRandomPool& prng);
void cryptoppDSASign(unsigned char* plainText, std::pair<CryptoPP::DSA::PublicKey, CryptoPP::DSA::PrivateKey> key, AutoSeededRandomPool& prng);
