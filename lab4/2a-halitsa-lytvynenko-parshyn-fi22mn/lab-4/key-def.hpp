#pragma once

#include <vector>;
#include <map>;

#include "./big-number.hpp";
#include "./definitions.hpp";


static enum class KeyType {
	_public,
	_private,
	_secret
};

static enum class KeyUsage {
	encrypt,
	decrypt,
	sign,
	verify
};

struct Key {
	KeyType type;
	AlgorithmIdentifier algorithm;
	std::vector<KeyUsage> usages;
	std::map<std::string, BigNumber> value;

	Key(const KeyType &type, const AlgorithmIdentifier &algorithm, const std::vector<KeyUsage> &usages, const std::map<std::string, BigNumber> &value);
};
