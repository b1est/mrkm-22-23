#pragma once
#include "utils.h"

#include <string>

#include <openssl/sha.h>

unsigned char* string_to_sha256(const std::string str)
{
	unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
	return SHA256((unsigned char*)str.c_str(), str.size(), hash);
}
