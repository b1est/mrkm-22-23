#pragma warning(disable: 4996)

#include <iostream>;
#include <chrono>;

#include <openssl/applink.c>;

#include "random.hpp";
#include "openssl.hpp";
#include "cryptopp.hpp";



int main(void)
{
    unsigned short iterationsCount = 10;

    // -----------------------------------OPENSSL-----------------------------------
    std::cout << "-----------------------------------OPENSSL-----------------------------------" << std::endl;

    // AES-256, plain text size = 128 bit
    std::cout << "AES-256, plain text size = 128 bit" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountSmall, plaintTextBlockSmall);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountSmall; ++i)
            {
                opensslAESEncrypt(randomData["plainTexts"][i], randomData["keys"][i], randomData["salts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountSmall);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // AES-256, plain text size = 16384 bit (128 blocks of 128 bit)
    std::cout << "AES-256, plain text size = 16384 bit (128 blocks of 128 bit)" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountBig, plaintTextBlockBig);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountBig; ++i)
            {
                opensslAESEncrypt(randomData["plainTexts"][i], randomData["keys"][i], randomData["salts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountBig);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // AES-256, plain text size = 1 gigabyte
    std::cout << "AES-256, plain text size = 1 gigabyte" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(1, gigaByte);

            auto start = std::chrono::high_resolution_clock::now();

            opensslAESEncrypt(randomData["plainTexts"][0], randomData["keys"][0], randomData["salts"][0]);

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, 1);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // SHA3-256, plain text size = 128 bit
    std::cout << "SHA3-256, plain text size = 128 bit" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountSmall, plaintTextBlockSmall);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountSmall; ++i)
            {
                opensslSHA3(randomData["plainTexts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountSmall);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // SHA3-256, plain text size = 16384 bit (128 blocks of 128 bit)
    std::cout << "SHA3-256, plain text size = 16384 bit (128 blocks of 128 bit)" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountBig, plaintTextBlockBig);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountBig; ++i)
            {
                opensslSHA3(randomData["plainTexts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountBig);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // SHA3-256, plain text size = 1 gigabyte
    std::cout << "SHA3-256, plain text size = 1 gigabyte" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(1, gigaByte);

            auto start = std::chrono::high_resolution_clock::now();

            opensslSHA3(randomData["plainTexts"][0]);

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, 1);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // DSA-1024, plain text size = 128 bit
    std::cout << "DSA 1024, plain text size = 128 bit" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountSmall, plaintTextBlockSmall);

            auto start = std::chrono::high_resolution_clock::now();

            auto key = opensslDSAGenerateKey(1024);

            for (int i = 0; i < blocksCountSmall; ++i)
            {
                opensslDSASign(randomData["plainTexts"][i], key);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountSmall);
            EVP_PKEY_free(key);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // DSA-1024, plain text size = 16384 bit (128 blocks of 128 bit)
    std::cout << "DSA 1024, plain text size = 16384 bit (128 blocks of 128 bit)" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountBig, plaintTextBlockBig);

            auto start = std::chrono::high_resolution_clock::now();

            auto key = opensslDSAGenerateKey(1024);

            for (int i = 0; i < blocksCountBig; ++i)
            {
                opensslDSASign(randomData["plainTexts"][i], key);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountBig);
            EVP_PKEY_free(key);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // DSA-1024, plain text size = 1 gigabyte
    std::cout << "DSA 1024, plain text size = 1 gigabyte" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(1, gigaByte);

            auto start = std::chrono::high_resolution_clock::now();

            auto key = opensslDSAGenerateKey(1024);

            opensslDSASign(randomData["plainTexts"][0], key);

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, 1);
            EVP_PKEY_free(key);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // -----------------------------------CRYPTO++-----------------------------------
    std::cout << "-----------------------------------CRYPTO++-----------------------------------" << std::endl;

    // AES-256, plain text size = 128 bit
    std::cout << "AES-256, plain text size = 128 bit" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountSmall, plaintTextBlockSmall);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountSmall; ++i)
            {
                cryptoppAESEncrypt(randomData["plainTexts"][i], randomData["keys"][i], randomData["salts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountSmall);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // AES-256, plain text size = 16384 bit (128 blocks of 128 bit)
    std::cout << "AES-256, plain text size = 16384 bit (128 blocks of 128 bit)" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountBig, plaintTextBlockBig);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountBig; ++i)
            {
                cryptoppAESEncrypt(randomData["plainTexts"][i], randomData["keys"][i], randomData["salts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountBig);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // AES-256, plain text size = 1 gigabyte
    std::cout << "AES-256, plain text size = 1 gigabyte" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(1, gigaByte);

            auto start = std::chrono::high_resolution_clock::now();

            opensslAESEncrypt(randomData["plainTexts"][0], randomData["keys"][0], randomData["salts"][0]);

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, 1);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // SHA3-256, plain text size = 128 bit
    std::cout << "SHA3-256, plain text size = 128 bit" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountSmall, plaintTextBlockSmall);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountSmall; ++i)
            {
                cryptoppSHA3(randomData["plainTexts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountSmall);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // SHA3-256, plain text size = 16384 bit (128 blocks of 128 bit)
    std::cout << "SHA3-256, plain text size = 16384 bit (128 blocks of 128 bit)" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountBig, plaintTextBlockBig);

            auto start = std::chrono::high_resolution_clock::now();

            for (int i = 0; i < blocksCountBig; ++i)
            {
                cryptoppSHA3(randomData["plainTexts"][i]);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountBig);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // SHA3-256, plain text size = 1 gigabyte
    std::cout << "SHA3-256, plain text size = 1 gigabyte" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(1, gigaByte);

            auto start = std::chrono::high_resolution_clock::now();

            cryptoppSHA3(randomData["plainTexts"][0]);

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, 1);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }


    // DSA 1024, plain text size = 128 bit
    std::cout << "DSA 1024, plain text size = 128 bit" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountSmall, plaintTextBlockSmall);

            auto start = std::chrono::high_resolution_clock::now();

            AutoSeededRandomPool prng;
            auto key = cryptoppDSAGenerateKey(1024, prng);

            for (int i = 0; i < blocksCountSmall; ++i)
            {
                cryptoppDSASign(randomData["plainTexts"][i], key, prng);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountSmall);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }


    // DSA 1024, plain text size = 16384 bit (128 blocks of 128 bit)
    std::cout << "DSA 1024, plain text size = 16384 bit (128 blocks of 128 bit)" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(blocksCountBig, plaintTextBlockBig);

            auto start = std::chrono::high_resolution_clock::now();

            AutoSeededRandomPool prng;
            auto key = cryptoppDSAGenerateKey(1024, prng);

            for (int i = 0; i < blocksCountBig; ++i)
            {
                cryptoppDSASign(randomData["plainTexts"][i], key, prng);
            }

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, blocksCountBig);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    // DSA-1024, plain text size = 1 gigabyte
    std::cout << "DSA 1024, plain text size = 1 gigabyte" << std::endl;

    {
        std::chrono::duration<double> duration = std::chrono::nanoseconds(0);

        for (int i = 0; i < iterationsCount; ++i)
        {
            auto randomData = randomSetGenerator(1, gigaByte);

            auto start = std::chrono::high_resolution_clock::now();

            AutoSeededRandomPool prng;
            auto key = cryptoppDSAGenerateKey(1024, prng);

            cryptoppDSASign(randomData["plainTexts"][0], key, prng);

            auto end = std::chrono::high_resolution_clock::now();

            freeMemoryAfterRandom(randomData, 1);

            duration += end - start;
        }

        std::cout << duration.count() * 1000 / iterationsCount << "ms" << std::endl;
    }

    return 0;
}
