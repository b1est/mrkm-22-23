#include "cryptopp.hpp";


void cryptoppAESEncrypt(const unsigned char* plainText, const unsigned char* plainKey, const unsigned char* salt)
{
    HexEncoder encoder(new FileSink(std::cout));
    SecByteBlock key(AES::MAX_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    std::string cipher;

    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(plainKey, key.size(), salt);

    StringSource s(static_cast<std::string>((char*)plainText), true,
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter
    ); // StringSource
}


void cryptoppSHA3(const unsigned char* plainText)
{
    HexEncoder encoder(new FileSink(std::cout));

    std::string message = static_cast<std::string>((char*)plainText);
    std::string digest;

    SHA3_256 hash;
    hash.Update((const byte*)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
}

std::pair<DSA::PublicKey, DSA::PrivateKey> cryptoppDSAGenerateKey(unsigned int keyLength, AutoSeededRandomPool &prng)
{
    HexEncoder encoder(new FileSink(std::cout));
    DSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(prng, keyLength);

    DSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    return std::make_pair(publicKey, privateKey);
}

void cryptoppDSASign(unsigned char* plainText, std::pair<DSA::PublicKey, DSA::PrivateKey> key, AutoSeededRandomPool& prng)
{
    std::string message = static_cast<std::string>((char*)plainText);
    std::string signature;
    std::string output;

    DSA::Signer signer(key.second);
    StringSource(message, true,
        new SignerFilter(prng, signer, new StringSink(signature))
    );
}
