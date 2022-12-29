#pragma once

#include <map>;

#include "./big-number.hpp";
#include "./definitions.hpp";
#include "./key-def.hpp";
#include "./el-gamal.hpp";


class CryptoSubtle {
public:
	static std::map<KeyType, Key> generateKey(
		const AlgorithmIdentifier& algorithm,
		const std::vector<KeyUsage>& usages
	);

	static std::map<std::string, BigNumber> encrypt(
		const AlgorithmIdentifier &algorithm,
		const Key &key,
		const BigNumber& data
	);

	static BigNumber decrypt(
		const AlgorithmIdentifier& algorithm,
		const std::map<KeyType, Key>& key,
		const std::map<std::string, BigNumber>& data
	);

	static std::map<std::string, BigNumber> sign(
		const AlgorithmIdentifier& algorithm,
		const std::map<KeyType, Key>& key,
		const BigNumber& data
	);

	static bool verify(
		const AlgorithmIdentifier& algorithm,
		const Key& key,
		const std::map<std::string, BigNumber>& signature,
		const BigNumber& data
	);
};
