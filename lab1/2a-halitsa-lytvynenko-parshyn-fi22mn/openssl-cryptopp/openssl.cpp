#include "openssl.hpp";


std::pair<unsigned char*, int> opensslAESEncrypt(const unsigned char* plainText, const unsigned char* key, const unsigned char* salt, bool needReturn)
{
    auto plainTextLength = strlen((char*)plainText);

    EVP_CIPHER_CTX* cipherContext = EVP_CIPHER_CTX_new();

    auto cipherText = new unsigned char[plainTextLength * 2];
    int length;

    EVP_EncryptInit_ex(cipherContext, EVP_aes_256_cbc(), NULL, key, salt);

    EVP_EncryptUpdate(cipherContext, cipherText, &length, plainText, plainTextLength);
    int cipherTextLength = length;

    EVP_EncryptFinal_ex(cipherContext, cipherText + length, &length);
    cipherTextLength += length;

    EVP_CIPHER_CTX_free(cipherContext);

    if (needReturn == false)
    {
        delete[] cipherText;
        cipherText = nullptr;
    }

    return std::make_pair(cipherText, cipherTextLength);
}

unsigned char* opensslAESDecrypt(const std::pair<unsigned char*, int> cipherText, const unsigned char* key, const unsigned char* salt)
{
    auto cipherTextLength = strlen((char*)cipherText.first);

    EVP_CIPHER_CTX* cipherContext = EVP_CIPHER_CTX_new();

    auto plainText = new unsigned char[cipherTextLength * 2];
    int length;

    EVP_DecryptInit_ex(cipherContext, EVP_aes_256_cbc(), NULL, key, salt);

    EVP_DecryptUpdate(cipherContext, plainText, &length, cipherText.first, cipherText.second);
    int plainTextLength = length;

    EVP_DecryptFinal_ex(cipherContext, plainText + length, &length);
    plainTextLength += length;

    EVP_CIPHER_CTX_free(cipherContext);

    plainText[plainTextLength] = '\0';

    return plainText;
}

unsigned char* opensslSHA3(const unsigned char* plainText, bool needReturn)
{
    auto plainTextLength = strlen((char*)plainText);

    EVP_MD_CTX* digestContext = EVP_MD_CTX_new();

    EVP_DigestInit_ex(digestContext, EVP_sha256(), NULL);
    EVP_DigestUpdate(digestContext, plainText, plainTextLength);

    unsigned int digestLength = SHA256_DIGEST_LENGTH;
    auto digest = static_cast<unsigned char*>(OPENSSL_malloc(digestLength));

    EVP_DigestFinal_ex(digestContext, digest, &digestLength);

    EVP_MD_CTX_free(digestContext);

    if (needReturn == false)
    {
        OPENSSL_free(digest);
    }
       
    return digest;
}

EVP_PKEY* opensslDSAGenerateKey(unsigned int keyLength)
{
    EVP_PKEY_CTX* paramsContext = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    EVP_PKEY_paramgen_init(paramsContext);

    EVP_PKEY_CTX_set_dsa_paramgen_bits(paramsContext, keyLength);

    EVP_PKEY* params = NULL;
    EVP_PKEY_paramgen(paramsContext, &params);

    EVP_PKEY_CTX* keyContext = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(keyContext);


    EVP_PKEY* key = NULL;
    EVP_PKEY_keygen(keyContext, &key);

    //fprintf(stdout, "Generating public/private key pair:\n");
    //EVP_PKEY_print_private_fp(stdout, key, 4, NULL);
    //fprintf(stdout, "\n");

    EVP_PKEY_CTX_free(paramsContext);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(keyContext);

    return key;
}

std::pair<unsigned char*, int> opensslDSASign(unsigned char* plainText, EVP_PKEY* key, bool needReturn)
{
    auto plainTextLength = strlen((char*)plainText);

    EVP_MD_CTX* digestContext = EVP_MD_CTX_create();
    const EVP_MD* digestFunction = EVP_sha256();

    EVP_DigestInit_ex(digestContext, digestFunction, NULL);

    EVP_DigestSignInit(digestContext, NULL, digestFunction, NULL, key);

    EVP_DigestSignUpdate(digestContext, plainText, plainTextLength);

    size_t signLength = 0;
    EVP_DigestSignFinal(digestContext, NULL, &signLength);
    unsigned char* sign = static_cast<unsigned char*>(OPENSSL_malloc(signLength));

    EVP_MD_CTX_free(digestContext);

    //fprintf(stdout, "Generating signature:\n");
    //BIO_dump_indent_fp(stdout, sign, signLength, 2);
    //fprintf(stdout, "\n");

    if (needReturn == false)
    {
        OPENSSL_free(sign);
    }

    return std::make_pair(nullptr, signLength);
}
