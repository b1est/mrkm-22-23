#pragma once

#include "./el-gamal.hpp";


uint64_t ElGamal::keyLength = 2048;

std::map<KeyType, Key> ElGamal::generateKey(const std::vector<KeyUsage>& usages)
{
    auto p = rand_prime_big_number(keyLength);
    auto q = (p - 1) / 2;
    auto g = BigNumber::sqr_mod(rand_big_number(keyLength - 1, -1), p);
    auto x = rand_big_number(keyLength - 2, 0);
    auto y = BigNumber::exp_mod(g, x, p);

    auto publicKey = Key(
        KeyType::_public,
        AlgorithmIdentifier::ElGamal,
        usages,
        { { "p", p }, { "q", q }, { "g", g }, { "y", y } } 
   );

    auto privateKey = Key(
        KeyType::_private,
        AlgorithmIdentifier::ElGamal,
        usages,
        { { "x", x } }
    );

    return {
        { KeyType::_public, publicKey },
        { KeyType::_private, privateKey }
    };
}

std::map<std::string, BigNumber> ElGamal::encrypt(const Key &key, const BigNumber& data)
{
    if (
        key.algorithm == AlgorithmIdentifier::ElGamal && key.type == KeyType::_public &&
        std::find(key.usages.begin(), key.usages.end(), KeyUsage::encrypt) != key.usages.end()
    )
    {
        BigNumber k = rand_big_number(keyLength - 2, 0);

        auto p = key.value.at("p");
        auto g = key.value.at("g");
        auto y = key.value.at("y");

        auto c = std::pair<BigNumber, BigNumber>();

        c.first = BigNumber::exp_mod(g, k, p);
        c.second = (data * BigNumber::exp_mod(y, k, p)) % p;

        return { { "c_1", c.first }, { "c_2", c.second }};
    }

    std::cout << "Incorrect params!" << std::endl;
}

BigNumber ElGamal::decrypt(const std::map<KeyType, Key>& key, const std::map<std::string, BigNumber>& data)
{
    auto publicKey = key.at(KeyType::_public);
    auto privateKey = key.at(KeyType::_private);

    if (
        publicKey.algorithm == AlgorithmIdentifier::ElGamal && publicKey.type == KeyType::_public &&
        privateKey.algorithm == AlgorithmIdentifier::ElGamal && privateKey.type == KeyType::_private &&
        std::find(publicKey.usages.begin(), publicKey.usages.end(), KeyUsage::decrypt) != publicKey.usages.end() &&
        std::find(privateKey.usages.begin(), privateKey.usages.end(), KeyUsage::decrypt) != privateKey.usages.end()
    )
    {
        auto p = publicKey.value.at("p");
        auto x = privateKey.value.at("x");

        auto c_1 = data.at("c_1");
        auto c_2 = data.at("c_2");

        return (c_2 * BigNumber::exp_mod(c_1, -x % (p - 1), p)) % p;
    }

    std::cout << "Incorrect params!" << std::endl;
}

std::map<std::string, BigNumber> ElGamal::sign(const std::map<KeyType, Key>& key, const BigNumber& data)
{
    auto publicKey = key.at(KeyType::_public);
    auto privateKey = key.at(KeyType::_private);

    if (
        publicKey.algorithm == AlgorithmIdentifier::ElGamal && publicKey.type == KeyType::_public &&
        privateKey.algorithm == AlgorithmIdentifier::ElGamal && privateKey.type == KeyType::_private &&
        std::find(publicKey.usages.begin(), publicKey.usages.end(), KeyUsage::sign) != publicKey.usages.end() &&
        std::find(privateKey.usages.begin(), privateKey.usages.end(), KeyUsage::sign) != privateKey.usages.end()
    )
    {
        BigNumber k = rand_big_number(keyLength - 2, 0);

        auto p = publicKey.value.at("p");
        auto q = publicKey.value.at("q");
        auto g = publicKey.value.at("g");
        auto x = privateKey.value.at("x");

        auto sign = std::pair<BigNumber, BigNumber>();

        sign.first = BigNumber::exp_mod(g, k, p);
        sign.second = (data - sign.first * x) * BigNumber::exp_mod(k, q - 2, q) % q;

        return { { "r", sign.first }, { "s", sign.second } };
    }

    std::cout << "Incorrect params!" << std::endl;
}

bool ElGamal::verify(const Key& key, const std::map<std::string, BigNumber>& signature, const BigNumber& data)
{
    if (
        key.algorithm == AlgorithmIdentifier::ElGamal && key.type == KeyType::_public &&
        std::find(key.usages.begin(), key.usages.end(), KeyUsage::verify) != key.usages.end()
    )
    {
        BigNumber k = rand_big_number(keyLength - 2, 0);

        auto p = key.value.at("p");
        auto g = key.value.at("g");
        auto y = key.value.at("y");

        auto r = signature.at("r");
        auto s = signature.at("s");

        BigNumber leftPart = BigNumber::exp_mod(y, r, p) * BigNumber::exp_mod(r, s, p) % p;
        BigNumber rightPart = BigNumber::exp_mod(g, data, p);

        return leftPart == rightPart;
    }

    std::cout << "Incorrect params!" << std::endl;
}
