#pragma once

#include "./crypto-subtle.hpp";


std::map<KeyType, Key> CryptoSubtle::generateKey(
	const AlgorithmIdentifier& algorithm,
	const std::vector<KeyUsage>& usages
) {
	switch (algorithm)
	{
	case ElGamal:
		return ElGamal::generateKey(usages);
	}

	std::cout << "This algorithm is not implemented!" << std::endl;
}

std::map<std::string, BigNumber> CryptoSubtle::encrypt(
	const AlgorithmIdentifier& algorithm,
	const Key& key,
	const BigNumber& data
) {
	switch (algorithm)
	{
	case ElGamal:
		return ElGamal::encrypt(key, data);
	}

	std::cout << "This algorithm is not implemented!" << std::endl;
}

BigNumber CryptoSubtle::decrypt(
	const AlgorithmIdentifier& algorithm,
	const std::map<KeyType, Key>& key,
	const std::map<std::string, BigNumber>& data
) {
	switch (algorithm)
	{
	case ElGamal:
		return ElGamal::decrypt(key, data);
	}

	std::cout << "This algorithm is not implemented!" << std::endl;
}

std::map<std::string, BigNumber> CryptoSubtle::sign(
	const AlgorithmIdentifier& algorithm,
	const std::map<KeyType, Key>& key,
	const BigNumber& data
) {
	switch (algorithm)
	{
		case ElGamal:
			return ElGamal::sign(key, data);
	}

	std::cout << "This algorithm is not implemented!" << std::endl;
}

bool CryptoSubtle::verify(
	const AlgorithmIdentifier& algorithm,
	const Key& key,
	const std::map<std::string, BigNumber>& signature,
	const BigNumber& data
) {
	switch (algorithm)
	{
	case ElGamal:
		return ElGamal::verify(key, signature, data);
	}

	std::cout << "This algorithm is not implemented!" << std::endl;
}
