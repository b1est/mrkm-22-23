#include "random.hpp";


std::map<std::string, unsigned char**> randomSetGenerator(unsigned int blocksCount, unsigned int plaintTextBlockSize)
{
    auto randomKeys = new unsigned char*[blocksCount];
    auto randomSalts = new unsigned char*[blocksCount];
    auto randomPlainTexts = new unsigned char*[blocksCount];

    for (unsigned int i = 0; i < blocksCount; ++i)
    {
        randomizationEngine.seed(randomDevice());

        randomKeys[i] = new unsigned char[keySize];
        randomSalts[i] = new unsigned char[saltSize];
        randomPlainTexts[i] = new unsigned char[plaintTextBlockSize + 1];

        for (unsigned int j = 0; j < keySize; ++j)
        {
            randomKeys[i][j] = randomVariable(randomizationEngine);
        }

        for (unsigned int j = 0; j < saltSize; ++j)
        {
            randomSalts[i][j] = randomVariable(randomizationEngine);
        }

        for (unsigned int j = 0; j < plaintTextBlockSize; ++j)
        {
            randomPlainTexts[i][j] = randomVariableWithoutZero(randomizationEngine);
        }

        randomPlainTexts[i][plaintTextBlockSize] = '\0';
    }

    return
    {
        {"keys", randomKeys},
        {"salts", randomSalts},
        {"plainTexts", randomPlainTexts}
    };
}

void freeMemoryAfterRandom(std::map<std::string, unsigned char**> &randomData, unsigned int blocksCount)
{
    for (unsigned int i = 0; i < blocksCount; ++i)
    {
        delete[] randomData["keys"][i];
        delete[] randomData["salts"][i];
        delete[] randomData["plainTexts"][i];
    }

    delete randomData["keys"];
    delete randomData["salts"];
    delete randomData["plainTexts"];
}
