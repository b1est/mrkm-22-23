#pragma once
#include <chrono>

#define CRYPTO_RSA_KEY_LEN 2048
#define NUM_TESTS 1000
#define MESSAGE "hello"

using clock_tt = std::chrono::high_resolution_clock;
using second_t = std::chrono::duration<double, std::ratio<1> >;