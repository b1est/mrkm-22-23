#pragma once


#include "./key-def.hpp";


Key::Key(
	const KeyType& type,
	const AlgorithmIdentifier& algorithm,
	const std::vector<KeyUsage> &usages,
	const std::map<std::string, BigNumber> &value
)
{
	this->type = type;
	this->algorithm = algorithm;
	this->usages = usages;
	this->value = value;
}
