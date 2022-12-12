#include <cryptopp/rsa.h>
// To get random bytes
#include <cryptopp/osrng.h>

// couts
#include <iostream>
// vectors
#include <vector>
// to gete current time timestamp
#include <chrono>

int main() {
	std::vector<int> key_lengths = { 4096};
	CryptoPP::AutoSeededRandomPool rng;

	for (int key_length: key_lengths) {
		int signer_cycles = 0;
		int verification_cycles = 0;
		int length;
		int64_t start, finish;

		// Create Keys
		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(rng, key_length);
		CryptoPP::RSA::PublicKey publicKey(privateKey);

		// Generate message with needed bytes count
		std::vector<CryptoPP::byte> msg(256);
		rng.GenerateBlock(msg.data(), msg.size());

		// Sign and Encode
		CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

		// Create signature space
		std::vector<CryptoPP::byte> signature(signer.MaxSignatureLength());

		start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
		finish = start;
		while (finish - start < 10000) {
			length = signer.SignMessage(rng, msg.data(), msg.size(), signature.data());
			// update signature cycle
			signer_cycles++;

			// Set last timeout
			finish = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
		}

		// print the result
		std::cout << "Doing " << key_length << " bits private rsa's for 10s: " << signer_cycles << " " << key_length << " bits private RSA's in " << std::format("{:.2f}", float(finish - start) / 1000) << "s" << std::endl;

		// Resize now we know the true size of the signature
		signature.resize(length);

		////////////////////////////////////////////////
		// Verify and Recover
		CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

		start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
		finish = start;
		while (finish - start < 10000) {
			if (!verifier.VerifyMessage(msg.data(),
				msg.size(), signature.data(), signature.size()))
			{
				std::cout << "WTF, SOMETHING WRONG!!!!!!!!!!!!!!!!!!!!";
				exit(1);
			}

			// update verification cycle
			verification_cycles++;

			// Set last timeout
			finish = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
		}

		// print the result
		std::cout << "Doing " << key_length << " bits public rsa's for 10s: " << verification_cycles << " " << key_length << " bits public RSA's in " << std::format("{:.2f}", float(finish - start) / 1000) << "s" << std::endl;

		// print summary
		std::cout << " \t\tsign \t\tverify \t\tsign/s \t\tverify/s" << std::endl;
		std::cout << "rsa " << key_length << " bits \t" << std::format("{:.6f}", 10 / float(signer_cycles)) << "s \t" << std::format("{:.6f}", 10 / float(verification_cycles)) << "s \t" << std::format("{:.2f}", float(signer_cycles) / 10) << " \t\t" << std::format("{:.6f}", float(verification_cycles) / 10) << std::endl;
		std::cout << std::endl;
	}
	return 0;
}