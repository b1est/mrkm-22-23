#include "ElGamal.h"
#include "CryptoAPI.h"
#include <iostream>
#include <string>


void check_el_gamal() {
	std::string msg1 = "Some message is present here!1";
	std::string msg2 = "Some message is present here!2";

	El_Gamal* el_gamal_ctx = ElGamal_init();

	ElGamal_generate_private_key(el_gamal_ctx);
	ElGamal_generate_public_key(el_gamal_ctx);

	El_Gamal_ciphertext* ct = NULL;
	ElGamal_encrypt(el_gamal_ctx, msg1, ct);
	std::string decrypted = "";
	ElGamal_decrypt(el_gamal_ctx, decrypted, ct);

	El_Gamal_signature* signature = NULL;
	ElGamal_sign(el_gamal_ctx, msg1, signature);
	int verification_true = ElGamal_verify(el_gamal_ctx, msg1, signature);
	int verification_false = ElGamal_verify(el_gamal_ctx, msg2, signature);

	std::cout << "Original message: " << msg1 << std::endl;
	std::cout << "Encrypted message: a = ";
	BN_print_fp(stdout, ct->a);
	std::cout << "; b = ";
	BN_print_fp(stdout, ct->b);
	std::cout << std::endl;
	std::cout << "Decrypted message: " << decrypted.c_str() << std::endl;
	std::cout << "Signing message: " << msg1 << std::endl;
	std::cout << "Signature: r = ";
	BN_print_fp(stdout, signature->r);
	std::cout << "; s = ";
	BN_print_fp(stdout, signature->s);
	std::cout << std::endl;
	std::cout << "Verify this message with signature: " << msg1 << "; Result: " << verification_true << std::endl;
	std::cout << "Verify this message with signature: " << msg2 << "; Result: " << verification_false << std::endl;

	ElGamal_signature_free(signature);
	ElGamal_ciphertext_free(ct);
	ElGamal_free(el_gamal_ctx);
}


void check_crypto_wrapper() {
	std::string msg1 = "Some message is present here!1";
	std::string msg2 = "Some message is present here!2";

	Wrapper* el_gamal = new Wrapper();

	el_gamal->generate_private_key();
	el_gamal->generate_public_key();

	El_Gamal_ciphertext* ct;
	ct = el_gamal->encrypt(msg1);
	std::string decrypted;
	decrypted = el_gamal->decrypt(ct);

	El_Gamal_signature* signature;
	signature = el_gamal->sign(msg1);
	bool verification_true = el_gamal->verify(msg1, signature);
	bool verification_false = el_gamal->verify(msg2, signature);

	std::cout << "Original message: " << msg1 << std::endl;
	std::cout << "Encrypted message: a = ";
	BN_print_fp(stdout, ct->a);
	std::cout << "; b = ";
	BN_print_fp(stdout, ct->b);
	std::cout << std::endl;
	std::cout << "Decrypted message: " << decrypted.c_str() << std::endl;
	std::cout << "Signing message: " << msg1 << std::endl;
	std::cout << "Signature: r = ";
	BN_print_fp(stdout, signature->r);
	std::cout << "; s = ";
	BN_print_fp(stdout, signature->s);
	std::cout << std::endl;
	std::cout << "Verify this message with signature: " << msg1 << "; Result: " << verification_true << std::endl;
	std::cout << "Verify this message with signature: " << msg2 << "; Result: " << verification_false << std::endl;

	el_gamal->free_signature(signature);
	el_gamal->free_ciphertext(ct);
	el_gamal->del_private_key();
	el_gamal->del_public_key();
}

int main() {
	// check_el_gamal();
	check_crypto_wrapper();

	return 0;
}