#pragma once

#include <iostream>;
#include <random>;
#include <memory>;
#include <string>;

#include <openssl/evp.h>;
#include <openssl/sha.h>;
#include <openssl/dsa.h>;
#include <openssl/pem.h>;
#include <openssl/bio.h>;


std::pair<unsigned char*, int> opensslAESEncrypt(const unsigned char* plainText, const unsigned char* key, const unsigned char* salt, bool needReturn = false);
unsigned char* opensslAESDecrypt(const std::pair<unsigned char*, int> cipherText, const unsigned char* key, const unsigned char* salt);

unsigned char* opensslSHA3(const unsigned char* plainText, bool needReturn = false);

EVP_PKEY* opensslDSAGenerateKey(unsigned int keyLength);
std::pair<unsigned char*, int> opensslDSASign(unsigned char* plainText, EVP_PKEY* key, bool needReturn = false);
