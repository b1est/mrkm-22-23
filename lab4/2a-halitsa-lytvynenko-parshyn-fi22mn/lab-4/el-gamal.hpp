#pragma once

#include <map>;

#include "./big-number.hpp";
#include "./key-def.hpp";


class ElGamal
{
public:
    static uint64_t keyLength;

    static std::map<KeyType, Key> generateKey(
        const std::vector<KeyUsage>& usages
    );
    
    static std::map<std::string, BigNumber> encrypt(
        const Key& key,
        const BigNumber& data
    );
    
    static BigNumber decrypt(
        const std::map<KeyType, Key>& key,
        const std::map<std::string, BigNumber>& data
    );
    
    static std::map<std::string, BigNumber> sign(
        const std::map<KeyType, Key>& key,
        const BigNumber& data
    );
    
    static bool verify(
        const Key& key,
        const std::map<std::string, BigNumber>& signature,
        const BigNumber& data
    );
};