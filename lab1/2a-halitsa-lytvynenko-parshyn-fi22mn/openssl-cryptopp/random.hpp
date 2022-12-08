#pragma once

#include <random>;
#include <memory>;
#include <vector>;
#include <map>;


static std::random_device randomDevice;
static std::mt19937 randomizationEngine;
static std::uniform_int<unsigned short> randomVariable(0, UCHAR_MAX);
static std::uniform_int<unsigned short> randomVariableWithoutZero(1, UCHAR_MAX);

const unsigned short keySize = 32;
const unsigned short saltSize = 16;
const unsigned short plaintTextBlockSmall = 16;
const unsigned short plaintTextBlockBig = 2048;

const unsigned int gigaByte = 1024 * 1024 * 1024;
const unsigned int blocksCountSmall = gigaByte / plaintTextBlockSmall;
const unsigned int blocksCountBig = gigaByte / plaintTextBlockBig;

std::map<std::string, unsigned char**> randomSetGenerator(unsigned int blocksCount, unsigned int plaintTextBlockSize);
void freeMemoryAfterRandom(std::map<std::string, unsigned char**> &randomData, unsigned int blocksCount);
