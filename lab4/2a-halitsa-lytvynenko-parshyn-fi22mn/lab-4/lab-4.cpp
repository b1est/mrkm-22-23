#include <iostream>;

#include "./crypto-subtle.hpp";


int main()
{
	auto keys = CryptoSubtle::generateKey(
		AlgorithmIdentifier::ElGamal, 
		{ KeyUsage::encrypt, KeyUsage::decrypt, KeyUsage::sign, KeyUsage::verify }
	);

	{
		// Encrypting

		std::cout << "Encrypting\n" << std::endl;

		std::string m;

		std::cout << "Input message that will be encrypted:" << std::endl;
		std::cin >> m;

		std::cout << std::endl;

		auto cipherText = CryptoSubtle::encrypt(
			AlgorithmIdentifier::ElGamal,
			keys.at(KeyType::_public),
			m
		);

		std::cout << "c_1:\n" << cipherText.at("c_1") << std::endl;
		std::cout << "c_2:\n" << cipherText.at("c_2") << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	{
		// Decrypting

		std::cout << "Decrypting\n" << std::endl;

		std::string c_1, c_2;

		std::cout << "Input message that will be decrypted:" << std::endl;
		std::cout << "c_1: ";
		std::cin >> c_1;

		std::cout << "c_2: ";
		std::cin >> c_2;

		std::cout << std::endl;

		auto plainText = CryptoSubtle::decrypt(
			AlgorithmIdentifier::ElGamal,
			keys,
			{ { "c_1", c_1 }, { "c_2", c_2 } }
		);

		std::cout << "m: \n" << plainText << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	{
		// Signing

		std::cout << "Signing\n" << std::endl;

		std::string m;

		std::cout << "Input message that will be signed:" << std::endl;
		std::cin >> m;

		std::cout << std::endl;

		auto sign = CryptoSubtle::sign(
			AlgorithmIdentifier::ElGamal,
			keys,
			m
		);

		std::cout << "r:\n" << sign.at("r") << std::endl;
		std::cout << "s:\n" << sign.at("s") << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	{
		// Verifying

		std::cout << "Verifying\n" << std::endl;

		std::string m, r, s;

		std::cout << "Input message and sign that will be verified:" << std::endl;
		std::cout << "m: ";
		std::cin >> m;

		std::cout << "r: ";
		std::cin >> r;

		std::cout << "s: ";
		std::cin >> s;

		std::cout << std::endl;

		auto verifyResult = CryptoSubtle::verify(
			AlgorithmIdentifier::ElGamal,
			keys.at(KeyType::_public),
			{ { "r", r }, { "s", s } },
			m
		);

		std::cout << "Sign is correct: " << verifyResult << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	return 1;
}