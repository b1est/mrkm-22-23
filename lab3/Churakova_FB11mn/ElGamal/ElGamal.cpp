#include <openssl/bn.h>
#include <openssl/bnerr.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <openssl/sha.h>

unsigned char* string_to_sha256(const std::string str)
{
	unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
	return SHA256((unsigned char*)str.c_str(), str.size(), hash);
}

struct El_Gamal_signature {
	BIGNUM* r;
	BIGNUM* s;
};

struct El_Gamal_ciphertext {
	BIGNUM* a;
	BIGNUM* b;
};

struct El_Gamal_pub {
	BN_ULONG bits_p;
	BN_ULONG bits_g;
	BIGNUM* prime_p;
	BIGNUM* prime_g;
	BIGNUM* pub_y;
};

struct El_Gamal_priv {
	BIGNUM* priv_x;
};

struct El_Gamal_keys {
	El_Gamal_pub pub;
	El_Gamal_priv priv;
};

struct El_Gamal {
	El_Gamal_keys keys;
	BN_CTX* ctx;
};

El_Gamal_signature* ElGamal_signature_init() {
	El_Gamal_signature* signature = new El_Gamal_signature;
	signature->r = BN_new();
	signature->s = BN_new();
	return signature;
}

int ElGamal_sinature_free(El_Gamal_signature* signature) {
	BN_free(signature->r);
	BN_free(signature->s);
	return 1;
}

El_Gamal_ciphertext* ElGamal_ciphertext_init() {
	El_Gamal_ciphertext* ct = new El_Gamal_ciphertext;
	ct->a = BN_new();
	ct->b = BN_new();
	return ct;
}

int ElGamal_ciphertext_free(El_Gamal_ciphertext* ct) {
	BN_free(ct->a);
	BN_free(ct->b);
	return 1;
}

El_Gamal* ElGamal_init() {
	El_Gamal* el_gamal = new El_Gamal;
	el_gamal->keys.pub.prime_p = BN_new();
	el_gamal->keys.pub.prime_g = BN_new();
	el_gamal->keys.pub.pub_y = BN_new();
	el_gamal->keys.priv.priv_x = BN_secure_new();
	el_gamal->ctx = BN_CTX_secure_new();
	return el_gamal;
}

int ElGamal_free(El_Gamal* el_gamal) {
	BN_free(el_gamal->keys.pub.prime_p);
	BN_free(el_gamal->keys.pub.prime_g);
	BN_free(el_gamal->keys.pub.pub_y);
	BN_clear_free(el_gamal->keys.priv.priv_x);
	BN_CTX_free(el_gamal->ctx);
	delete el_gamal;
	return 1;
}

int ElGamal_rand_gen(El_Gamal* el_gamal, BN_ULONG bits_p = 1024, BN_ULONG bits_g = 512) {
	el_gamal->keys.pub.bits_g = bits_g;
	el_gamal->keys.pub.bits_p = bits_p;
	if (!BN_generate_prime_ex2(el_gamal->keys.pub.prime_p, bits_p, true, NULL, NULL, NULL, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(1);
	}
	if (!BN_generate_prime_ex2(el_gamal->keys.pub.prime_g, bits_g, true, NULL, NULL, NULL, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating prime_g num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(2);
	}
	if (!BN_sub_word(el_gamal->keys.pub.prime_p, 3)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(3);
	}
	if (!BN_priv_rand_range_ex(el_gamal->keys.priv.priv_x, el_gamal->keys.pub.prime_p, bits_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(4);
	}
	if (!BN_add_word(el_gamal->keys.priv.priv_x, 2)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(5);
	}
	if (!BN_add_word(el_gamal->keys.pub.prime_p, 3)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(6);
	}
	if (!BN_mod_exp(el_gamal->keys.pub.pub_y, el_gamal->keys.pub.prime_g, el_gamal->keys.priv.priv_x, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(7);
	}
	return 1;
}


BIGNUM* ELGamal_gen_session_key(El_Gamal* el_gamal) {
	BIGNUM* ses_key = BN_secure_new();

	BIGNUM* copy_p = BN_dup(el_gamal->keys.pub.prime_p);
	if (!BN_sub_word(copy_p, 3)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(8);
	}
	if (!BN_priv_rand_range_ex(ses_key, copy_p, el_gamal->keys.pub.bits_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}
	if (!BN_add_word(ses_key, 2)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(10);
	}
	BN_free(copy_p);

	return ses_key;
}


El_Gamal_ciphertext* ElGamal_encrypt(El_Gamal* el_gamal, std::string msg) {
	if (msg.length() * 8 >= el_gamal->keys.pub.bits_p) {
		std::cout << "Size of message can not exceed size of prime_p" << std::endl;
		exit(11);
	}

	BN_ULONG max_size = (el_gamal->keys.pub.bits_p - 1) / 8;
	BIGNUM* message_num = BN_bin2bn((unsigned char*)msg.c_str(), max_size, NULL);


	El_Gamal_ciphertext* ct = ElGamal_ciphertext_init();
	BIGNUM* ses_key = ELGamal_gen_session_key(el_gamal);

	if (!BN_mod_exp(ct->a, el_gamal->keys.pub.prime_g, ses_key, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(11);
	}
	if (!BN_mod_exp(ct->b, el_gamal->keys.pub.pub_y, ses_key, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(12);
	}
	BIGNUM* temp_b = BN_dup(ct->b);
	if (!BN_mod_mul(ct->b, temp_b, message_num, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(13);
	}

	BN_clear_free(temp_b);
	BN_clear_free(ses_key);
	BN_free(message_num);
	return ct;
}


std::string ElGamal_decrypt(El_Gamal* el_gamal, El_Gamal_ciphertext* ct) {
	std::string msg;
	BN_ULONG max_size = (el_gamal->keys.pub.bits_p - 1) / 8;

	unsigned char* msg_char = new unsigned char[max_size];
	BIGNUM* power = BN_secure_new();
	BIGNUM* temp = BN_secure_new();
	BIGNUM* message = BN_secure_new();

	if (!BN_copy(power, el_gamal->keys.pub.prime_p)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying prime_p to power: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(14);
	}
	if (!BN_sub_word(power, 1)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 from power: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(15);
	}
	if (!BN_sub(temp, power, el_gamal->keys.priv.priv_x)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting priv_x from power: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(16);
	}
	if (!BN_copy(power, temp)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying from temp to power: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(17);
	}
	if (!BN_mod_exp(temp, ct->a, power, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on getting result from a exp (p - 1 - x): \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(18);
	}
	if (!BN_mod_mul(message, ct->b, temp, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on getting message result: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(19);
	}

	BN_bn2binpad(message, msg_char, max_size);
	msg = std::string(reinterpret_cast<const char*>(msg_char), max_size);

	delete[] msg_char;
	BN_clear_free(message);
	BN_clear_free(power);
	BN_clear_free(temp);

	return msg;
}


BIGNUM* ELGamal_gen_session_key_signature(El_Gamal* el_gamal) {
	BIGNUM* ses_key = BN_secure_new();


	BIGNUM* add = BN_new();
	if (!BN_add_word(add, 4)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(8);
	}
	if (!BN_generate_prime_ex2(ses_key, el_gamal->keys.pub.bits_p - 1, 0, add, NULL, NULL, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating ses_key num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	BN_free(add);
	return ses_key;
}


El_Gamal_signature* ElGamal_sign(El_Gamal* el_gamal, std::string msg) {
	El_Gamal_signature* signature = ElGamal_signature_init();
	BIGNUM* hash_num = BN_bin2bn(string_to_sha256(msg), SHA256_DIGEST_LENGTH, NULL);
	BIGNUM* ses_key = ELGamal_gen_session_key_signature(el_gamal);
	BIGNUM* ses_key_inversed = BN_secure_new();
	BIGNUM* prime_p_sub_1 = BN_dup(el_gamal->keys.pub.prime_p);
	BIGNUM* priv_x_mul_r = BN_secure_new();
	BIGNUM* temp = BN_new();

	if (!BN_sub_word(prime_p_sub_1, 1)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(8);
	}

	if (!BN_mod_exp(signature->r, el_gamal->keys.pub.prime_g, ses_key, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_inverse(ses_key_inversed, ses_key, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod inverse: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_mul(priv_x_mul_r, el_gamal->keys.priv.priv_x, signature->r, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod mul: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_sub(temp, hash_num, priv_x_mul_r, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod sub: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_mul(signature->s, temp, ses_key_inversed, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod mul: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	BN_free(temp);
	BN_clear_free(ses_key_inversed);
	BN_free(prime_p_sub_1);
	BN_clear_free(priv_x_mul_r);
	BN_clear_free(ses_key);
	BN_free(hash_num);

	return signature;
}


bool ElGamal_verify(El_Gamal* el_gamal, std::string msg, El_Gamal_signature* signature) {
	bool result = false;

	BIGNUM* zero = BN_new();

	if (BN_cmp(signature->r, zero) != 1) {
		BN_free(zero);
		return false;
	}
	if (BN_cmp(signature->s, zero) != 1) {
		BN_free(zero);
		return false;
	}

	BN_free(zero);


	BIGNUM* prime_p_sub_1 = BN_dup(el_gamal->keys.pub.prime_p);
	if (!BN_sub_word(prime_p_sub_1, 1)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(8);
	}
	if (BN_cmp(signature->r, el_gamal->keys.pub.prime_p) != -1) {
		BN_free(prime_p_sub_1);
		return false;
	}
	if (BN_cmp(signature->r, prime_p_sub_1) != -1) {
		BN_free(prime_p_sub_1);
		return false;
	}

	BN_free(prime_p_sub_1);


	BIGNUM* hash_num = BN_bin2bn(string_to_sha256(msg), SHA256_DIGEST_LENGTH, NULL);
	BIGNUM* right_side = BN_new();
	BIGNUM* r_exp_s = BN_new();
	BIGNUM* y_exp_r = BN_new();
	BIGNUM* left_side = BN_new();

	if (!BN_mod_exp(right_side, el_gamal->keys.pub.prime_g, hash_num, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_exp(r_exp_s, signature->r, signature->s, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_exp(y_exp_r, el_gamal->keys.pub.pub_y, signature->r, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (!BN_mod_mul(left_side, r_exp_s, y_exp_r, el_gamal->keys.pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod mul: \t" << err_buf << std::endl;
		delete[] err_buf;
		exit(9);
	}

	if (BN_cmp(left_side, right_side) == 0) {
		result = true;
	}


	BN_free(hash_num);
	BN_free(right_side);
	BN_free(left_side);
	BN_free(r_exp_s);
	BN_free(y_exp_r);

	return result;
}


int main() {
	std::string msg1 = "Some message is present here!1";
	std::string msg2 = "Some message is present here!2";

	El_Gamal* el_gamal_ctx = ElGamal_init();

	ElGamal_rand_gen(el_gamal_ctx);

	El_Gamal_ciphertext* ct = ElGamal_encrypt(el_gamal_ctx, msg1);
	std::string decrypted = ElGamal_decrypt(el_gamal_ctx, ct);

	El_Gamal_signature* signature = ElGamal_sign(el_gamal_ctx, msg1);
	bool verification_true = ElGamal_verify(el_gamal_ctx, msg1, signature);
	bool verification_false = ElGamal_verify(el_gamal_ctx, msg2, signature);

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

	
	ElGamal_sinature_free(signature);
	ElGamal_ciphertext_free(ct);
	ElGamal_free(el_gamal_ctx);

	return 0;
}
