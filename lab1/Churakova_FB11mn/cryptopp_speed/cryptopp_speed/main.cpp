// To get random bytes
#include <cryptopp/osrng.h>
// To use secure blocks
#include <cryptopp/secblock.h>
// To use GCM mode
#include <cryptopp/gcm.h>
// To use Rijndael (AES)
#include <cryptopp/rijndael.h>

// couts
#include <iostream>
// vectors
#include <vector>
// to gete current time timestamp
#include <chrono>


int main() {
	// Define variables
	int full_cycle;
	int64_t start, finish;
	std::string type_str, bytes_per_sec;
	std::vector<int> key_list = { 16 };
	std::vector<int> byte_list = { 16, 64, 256, 1024, 8192, 16384 };
	CryptoPP::AutoSeededRandomPool rnd;
	

	// iterate through every possible key
	for (int key_length : key_list) {
		
		// init secret_key with random data
		CryptoPP::SecByteBlock secret_key(key_length);
		rnd.GenerateBlock(secret_key, secret_key.size());
		
		// init iv with random data
		CryptoPP::SecByteBlock iv(CryptoPP::Rijndael::BLOCKSIZE);
		rnd.GenerateBlock(iv, iv.size());
		
		// init strings
		type_str = "type \t\t";
		bytes_per_sec = "aes-" + std::to_string(key_length * 8) + " gcm\t";
		
		// iterate through all bytes
		for (int byte_val : byte_list) {
			// Init encrypted vector
			std::vector<CryptoPP::byte> encrypted_msg;

			// Generate message with needed bytes count
			std::vector<CryptoPP::byte> msg(byte_val);
			rnd.GenerateBlock(msg.data(), msg.size());
			
			// Initiate crypto object
			CryptoPP::GCM<CryptoPP::Rijndael>::Encryption obj;
			obj.SetKeyWithIV(secret_key, secret_key.size(), iv, iv.size());

			// set full_cycle to default 0
			full_cycle = 0;

			// Get start time timestamp
			start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
			finish = start;

			while (finish - start < 3000) {
				// Set to default state
				obj.SetKeyWithIV(secret_key, secret_key.size(), iv, iv.size());

				// Make room for padding
				encrypted_msg.resize(msg.size() + CryptoPP::Rijndael::BLOCKSIZE);
				CryptoPP::ArraySink cs(&encrypted_msg[0], encrypted_msg.size());

				// Encrypt
				CryptoPP::ArraySource(msg.data(), msg.size(), true,
					new CryptoPP::AuthenticatedEncryptionFilter
					(
						obj,
						new CryptoPP::Redirector(cs)
					)
				);

				// Set cipher text length now that its known
				encrypted_msg.resize(cs.TotalPutLength());

				// increment cycle
				full_cycle++;
				
				// Set last timeout
				finish = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
			}

			std::cout << "Doing aes-" << key_length * 8 << " gcm for 3s on " << byte_val << " size blocks: " << full_cycle << " aes-" << key_length * 8 << " gcm in " << std::format("{:.2f}", float(float(finish - start) / 1000)) << "'s" << std::endl;
			type_str += "\t " + std::to_string(byte_val) + " bytes";
			bytes_per_sec += "\t " + std::format("{:.2f}", float(full_cycle) / float(3) * float(byte_val) / float(1000)) + "k";
		}

		std::cout << "The 'numbers' are in 1000s of bytes per second processed." << std::endl;
		std::cout << type_str << std::endl;
		std::cout << bytes_per_sec << std::endl;
		std::cout << std::endl;
	}
	return 0;
}
