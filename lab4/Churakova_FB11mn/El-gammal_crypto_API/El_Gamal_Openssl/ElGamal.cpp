#include "ElGamal.h"
#include "utils.h"

#include <iostream>
#include <string>

#pragma once
#include "ElGamal.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>

El_Gamal_signature* ElGamal_signature_init() {
	El_Gamal_signature* signature = new El_Gamal_signature;
	signature->r = BN_new();
	signature->s = BN_new();
	return signature;
}

int ElGamal_signature_free(El_Gamal_signature*& signature) {
	BN_free(signature->r);
	BN_free(signature->s);
	signature->r = NULL;
	signature->s = NULL;
	delete signature;
	signature = NULL;
	return SUCCESS;
}

El_Gamal_ciphertext* ElGamal_ciphertext_init() {
	El_Gamal_ciphertext* ct = new El_Gamal_ciphertext;
	ct->a = BN_new();
	ct->b = BN_new();
	return ct;
}

int ElGamal_ciphertext_free(El_Gamal_ciphertext*& ct) {
	BN_free(ct->a);
	BN_free(ct->b);
	ct->a = NULL;
	ct->b = NULL;
	delete ct;
	ct = NULL;
	return SUCCESS;
}

int ElGamal_init_priv(El_Gamal* el_gamal) {
	if (el_gamal->keys.priv != NULL)
		return ALREADY_INITIALIZED;

	el_gamal->keys.priv = new El_Gamal_priv;

	el_gamal->keys.priv->priv_x = BN_secure_new();

	el_gamal->keys.priv->pub.bits_p = 0;
	el_gamal->keys.priv->pub.bits_g = 0;

	el_gamal->keys.priv->pub.prime_p = BN_secure_new();
	el_gamal->keys.priv->pub.prime_g = BN_secure_new();
	el_gamal->keys.priv->pub.pub_y = BN_secure_new();

	return SUCCESS;
}

int ElGamal_init_pub(El_Gamal* el_gamal) {
	if (el_gamal->keys.pub != NULL)
		return ALREADY_INITIALIZED;

	el_gamal->keys.pub = new El_Gamal_pub;

	el_gamal->keys.pub->bits_p = 0;
	el_gamal->keys.pub->bits_g = 0;

	el_gamal->keys.pub->prime_p = BN_new();
	el_gamal->keys.pub->prime_g = BN_new();
	el_gamal->keys.pub->pub_y = BN_new();

	return SUCCESS;
}

El_Gamal* ElGamal_init() {
	El_Gamal* el_gamal = new El_Gamal;
	el_gamal->keys.priv = NULL;
	el_gamal->keys.pub = NULL;
	el_gamal->ctx = BN_CTX_secure_new();
	return el_gamal;
}

int ElGamal_free_priv(El_Gamal* el_gamal) {
	if (el_gamal->keys.priv == NULL)
		return NO_PRIV;

	BN_clear_free(el_gamal->keys.priv->priv_x);
	el_gamal->keys.priv->priv_x = NULL;

	el_gamal->keys.priv->pub.bits_p = 0;
	el_gamal->keys.priv->pub.bits_g = 0;

	BN_clear_free(el_gamal->keys.priv->pub.prime_p);
	BN_clear_free(el_gamal->keys.priv->pub.prime_g);
	BN_clear_free(el_gamal->keys.priv->pub.pub_y);
	el_gamal->keys.priv->pub.prime_p = NULL;
	el_gamal->keys.priv->pub.prime_g = NULL;
	el_gamal->keys.priv->pub.pub_y = NULL;

	delete el_gamal->keys.priv;
	el_gamal->keys.priv = NULL;

	return SUCCESS;
}

int ElGamal_free_pub(El_Gamal* el_gamal) {
	if (el_gamal->keys.pub == NULL)
		return NO_PUB;

	el_gamal->keys.pub->bits_p = 0;
	el_gamal->keys.pub->bits_g = 0;

	BN_clear_free(el_gamal->keys.pub->prime_p);
	BN_clear_free(el_gamal->keys.pub->prime_g);
	BN_clear_free(el_gamal->keys.pub->pub_y);
	el_gamal->keys.pub->prime_p = NULL;
	el_gamal->keys.pub->prime_g = NULL;
	el_gamal->keys.pub->pub_y = NULL;

	delete el_gamal->keys.pub;
	el_gamal->keys.pub = NULL;

	return SUCCESS;
}

int ElGamal_free(El_Gamal*& el_gamal) {
	if (el_gamal->keys.pub != NULL)
		ElGamal_free_pub(el_gamal);

	if (el_gamal->keys.priv != NULL)
		ElGamal_free_priv(el_gamal);

	BN_CTX_free(el_gamal->ctx);
	delete el_gamal;
	el_gamal = NULL;

	return SUCCESS;
}

int ElGamal_generate_private_key(El_Gamal* el_gamal, BN_ULONG bits_p, BN_ULONG bits_g) {
	if (el_gamal->keys.priv != NULL)
		return ALREADY_GENERATED;
	if (el_gamal->keys.pub != NULL)
		ElGamal_free_pub(el_gamal);

	ElGamal_init_priv(el_gamal);

	el_gamal->keys.priv->pub.bits_g = bits_g;
	el_gamal->keys.priv->pub.bits_p = bits_p;
	if (!BN_generate_prime_ex2(el_gamal->keys.priv->pub.prime_p, bits_p, true, NULL, NULL, NULL, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (!BN_generate_prime_ex2(el_gamal->keys.priv->pub.prime_g, bits_g, true, NULL, NULL, NULL, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating prime_g num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (!BN_sub_word(el_gamal->keys.priv->pub.prime_p, 3)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (!BN_priv_rand_range_ex(el_gamal->keys.priv->priv_x, el_gamal->keys.priv->pub.prime_p, bits_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (!BN_add_word(el_gamal->keys.priv->priv_x, 2)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (!BN_add_word(el_gamal->keys.priv->pub.prime_p, 3)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (!BN_mod_exp(el_gamal->keys.priv->pub.pub_y, el_gamal->keys.priv->pub.prime_g, el_gamal->keys.priv->priv_x, el_gamal->keys.priv->pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_priv(el_gamal);

		return OPENSSL_BN_ERR;
	}
	return SUCCESS;
}

int ElGamal_generate_public_key(El_Gamal* el_gamal) {
	if (el_gamal->keys.pub != NULL)
		return ALREADY_GENERATED;
	if (el_gamal->keys.priv == NULL)
		return NO_PRIV;

	ElGamal_init_pub(el_gamal);

	el_gamal->keys.pub->bits_p = el_gamal->keys.priv->pub.bits_p;
	el_gamal->keys.pub->bits_g = el_gamal->keys.priv->pub.bits_g;

	if (BN_copy(el_gamal->keys.pub->prime_p, el_gamal->keys.priv->pub.prime_p) == NULL) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_pub(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (BN_copy(el_gamal->keys.pub->prime_g, el_gamal->keys.priv->pub.prime_g) == NULL) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying prime_g num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_pub(el_gamal);

		return OPENSSL_BN_ERR;
	}
	if (BN_copy(el_gamal->keys.pub->pub_y, el_gamal->keys.priv->pub.pub_y) == NULL) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying prime_g num: \t" << err_buf << std::endl;
		delete[] err_buf;
		ElGamal_free_pub(el_gamal);

		return OPENSSL_BN_ERR;
	}
	
	return SUCCESS;
}

int ELGamal_gen_session_key(El_Gamal* el_gamal, BIGNUM*& ses_key) {
	if (ses_key != NULL)
		return ALREADY_INITIALIZED;

	BIGNUM* prime_p;
	BN_ULONG bits_p;

	if (el_gamal->keys.priv != NULL) {
		prime_p = BN_dup(el_gamal->keys.priv->pub.prime_p);
		bits_p = el_gamal->keys.priv->pub.bits_p;
	}
	else if (el_gamal->keys.pub != NULL) {
		prime_p = BN_dup(el_gamal->keys.pub->prime_p);
		bits_p = el_gamal->keys.pub->bits_p;
	}
	else
		return NO_KEYS;

	ses_key = BN_secure_new();

	if (!BN_sub_word(prime_p, 3)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_clear_free(ses_key);
		ses_key = NULL;

		return OPENSSL_BN_ERR;
	}
	if (!BN_priv_rand_range_ex(ses_key, prime_p, bits_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_clear_free(ses_key);
		ses_key = NULL;

		return OPENSSL_BN_ERR;
	}
	if (!BN_add_word(ses_key, 2)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to priv_x num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_clear_free(ses_key);
		ses_key = NULL;

		return OPENSSL_BN_ERR;
	}
	BN_free(prime_p);

	return SUCCESS;
}


int ElGamal_encrypt(El_Gamal* el_gamal, std::string msg, El_Gamal_ciphertext*& ct) {
	if (ct != NULL)
		return ALREADY_INITIALIZED;
	
	BIGNUM* prime_p, *prime_g, *pub_y;
	BN_ULONG max_size;

	if (el_gamal->keys.priv != NULL) {
		prime_p = BN_dup(el_gamal->keys.priv->pub.prime_p);
		prime_g = BN_dup(el_gamal->keys.priv->pub.prime_g);
		pub_y = BN_dup(el_gamal->keys.priv->pub.pub_y);
		max_size = (el_gamal->keys.priv->pub.bits_p - 1) / 8;
	}
	else if (el_gamal->keys.pub != NULL) {
		prime_p = BN_dup(el_gamal->keys.pub->prime_p);
		prime_g = BN_dup(el_gamal->keys.pub->prime_g);
		pub_y = BN_dup(el_gamal->keys.pub->pub_y);
		max_size = (el_gamal->keys.pub->bits_p - 1) / 8;
	}
	else
		return NO_KEYS;

	if (msg.length() >= max_size) {
		std::cout << "Size of message can not exceed size of prime_p" << std::endl;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);

		return TOO_LARGE_MSG;
	}

	ct = ElGamal_ciphertext_init();

	BIGNUM* message_num, * ses_key;
	ses_key = NULL;
	message_num = BN_bin2bn((unsigned char*)msg.c_str(), max_size, NULL);

	ct = ElGamal_ciphertext_init();
	if (ELGamal_gen_session_key(el_gamal, ses_key) != SUCCESS) {
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_free(message_num);

		return SES_KEY_GEN_ERR;
	}

	if (!BN_mod_exp(ct->a, prime_g, ses_key, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_clear_free(ses_key);
		BN_free(message_num);

		return OPENSSL_BN_ERR;
	}
	if (!BN_mod_exp(ct->b, pub_y, ses_key, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_clear_free(ses_key);
		BN_free(message_num);

		return OPENSSL_BN_ERR;
	}
	BIGNUM* temp_b = BN_dup(ct->b);
	if (!BN_mod_mul(ct->b, temp_b, message_num, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on adding 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_clear_free(temp_b);
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_clear_free(ses_key);
		BN_free(message_num);

		return OPENSSL_BN_ERR;
	}
	BN_clear_free(temp_b);

	BN_free(prime_p);
	BN_free(prime_g);
	BN_free(pub_y);

	BN_clear_free(ses_key);
	BN_free(message_num);
	return SUCCESS;
}


int ElGamal_decrypt(El_Gamal* el_gamal, std::string &msg, El_Gamal_ciphertext* ct) {
	msg.clear();
	if (el_gamal->keys.priv == NULL)
		return NO_PRIV;
	if (ct == NULL || ct->a == NULL || ct->b == NULL)
		return NO_CT;

	BN_ULONG max_size = (el_gamal->keys.priv->pub.bits_p - 1) / 8;

	unsigned char* msg_char = new unsigned char[max_size];
	BIGNUM* power = BN_secure_new();
	BIGNUM* temp = BN_secure_new();
	BIGNUM* message = BN_secure_new();

	if (BN_copy(power, el_gamal->keys.priv->pub.prime_p) == NULL) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying prime_p to power: \t" << err_buf << std::endl;
		delete[] err_buf;
		delete[] msg_char;
		BN_clear_free(message);
		BN_clear_free(power);
		BN_clear_free(temp);

		return OPENSSL_BN_ERR;
	}
	if (!BN_sub_word(power, 1)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 from power: \t" << err_buf << std::endl;
		delete[] err_buf;
		delete[] msg_char;
		BN_clear_free(message);
		BN_clear_free(power);
		BN_clear_free(temp);

		return OPENSSL_BN_ERR;
	}
	if (!BN_sub(temp, power, el_gamal->keys.priv->priv_x)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting priv_x from power: \t" << err_buf << std::endl;
		delete[] err_buf;
		delete[] msg_char;
		BN_clear_free(message);
		BN_clear_free(power);
		BN_clear_free(temp);

		return OPENSSL_BN_ERR;
	}
	if (BN_copy(power, temp) == NULL) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on copying from temp to power: \t" << err_buf << std::endl;
		delete[] err_buf;
		delete[] msg_char;
		BN_clear_free(message);
		BN_clear_free(power);
		BN_clear_free(temp);

		return OPENSSL_BN_ERR;
	}
	if (!BN_mod_exp(temp, ct->a, power, el_gamal->keys.priv->pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on getting result from a exp (p - 1 - x): \t" << err_buf << std::endl;
		delete[] err_buf;
		delete[] msg_char;
		BN_clear_free(message);
		BN_clear_free(power);
		BN_clear_free(temp);

		return OPENSSL_BN_ERR;
	}
	if (!BN_mod_mul(message, ct->b, temp, el_gamal->keys.priv->pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on getting message result: \t" << err_buf << std::endl;
		delete[] err_buf;
		delete[] msg_char;
		BN_clear_free(message);
		BN_clear_free(power);
		BN_clear_free(temp);

		return OPENSSL_BN_ERR;
	}

	BN_bn2binpad(message, msg_char, max_size);
	msg = std::string(reinterpret_cast<const char*>(msg_char), max_size);

	delete[] msg_char;
	BN_clear_free(message);
	BN_clear_free(power);
	BN_clear_free(temp);

	return SUCCESS;
}


int ELGamal_gen_session_key_signature(El_Gamal* el_gamal, BIGNUM*& ses_key) {
	if (ses_key != NULL)
		return ALREADY_INITIALIZED;

	BN_ULONG bits_p;
	if (el_gamal->keys.priv != NULL) {
		bits_p = el_gamal->keys.priv->pub.bits_p;
	}
	else if (el_gamal->keys.pub != NULL) {
		bits_p = el_gamal->keys.pub->bits_p;
	}
	else
		return NO_KEYS;

	ses_key = BN_secure_new();

	BIGNUM* add = BN_new();
	if (!BN_add_word(add, 4)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(add);
		BN_clear_free(ses_key);
		ses_key = NULL;

		return OPENSSL_BN_ERR;
	}
	if (!BN_generate_prime_ex2(ses_key, bits_p - 1, 0, add, NULL, NULL, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on generating ses_key num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(add);
		BN_clear_free(ses_key);
		ses_key = NULL;

		return OPENSSL_BN_ERR;
	}
	BN_free(add);

	return SUCCESS;
}


int ElGamal_sign(El_Gamal* el_gamal, std::string msg, El_Gamal_signature*& signature) {
	if (signature != NULL)
		return ALREADY_INITIALIZED;
	if (el_gamal->keys.priv == NULL)
		return NO_PRIV;

	signature = ElGamal_signature_init();

	BIGNUM* prime_p_sub_1 = BN_dup(el_gamal->keys.priv->pub.prime_p);

	BIGNUM* hash_num = BN_bin2bn(string_to_sha256(msg), SHA256_DIGEST_LENGTH, NULL);
	BIGNUM* ses_key = NULL;
	BIGNUM* ses_key_inversed = BN_secure_new();
	BIGNUM* priv_x_mul_r = BN_secure_new();
	BIGNUM* temp = BN_new();

	if (ELGamal_gen_session_key_signature(el_gamal, ses_key) != SUCCESS) {
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_free(hash_num);
		ElGamal_signature_free(signature);
		return SES_KEY_GEN_ERR;
	}

	if (!BN_sub_word(prime_p_sub_1, 1)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_clear_free(ses_key);
		BN_free(hash_num);
		ElGamal_signature_free(signature);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_exp(signature->r, el_gamal->keys.priv->pub.prime_g, ses_key, el_gamal->keys.priv->pub.prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_clear_free(ses_key);
		BN_free(hash_num);
		ElGamal_signature_free(signature);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_inverse(ses_key_inversed, ses_key, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod inverse: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_clear_free(ses_key);
		BN_free(hash_num);
		ElGamal_signature_free(signature);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_mul(priv_x_mul_r, el_gamal->keys.priv->priv_x, signature->r, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod mul: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_clear_free(ses_key);
		BN_free(hash_num);
		ElGamal_signature_free(signature);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_sub(temp, hash_num, priv_x_mul_r, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod sub: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_clear_free(ses_key);
		BN_free(hash_num);
		ElGamal_signature_free(signature);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_mul(signature->s, temp, ses_key_inversed, prime_p_sub_1, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod mul: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(temp);
		BN_free(prime_p_sub_1);
		BN_clear_free(ses_key_inversed);
		BN_clear_free(priv_x_mul_r);
		BN_clear_free(ses_key);
		BN_free(hash_num);
		ElGamal_signature_free(signature);

		return OPENSSL_BN_ERR;
	}

	BN_free(temp);
	BN_free(prime_p_sub_1);
	BN_clear_free(ses_key_inversed);
	BN_clear_free(priv_x_mul_r);
	BN_clear_free(ses_key);
	BN_free(hash_num);

	return SUCCESS;
}


int ElGamal_verify(El_Gamal* el_gamal, std::string msg, El_Gamal_signature* signature) {
	if (signature == NULL || signature->r == NULL || signature->s == NULL)
		return NO_SIGNATURE;

	BIGNUM* zero = BN_new();
	if (BN_cmp(signature->r, zero) != 1) {
		BN_free(zero);
		return WRONG_SIGNATURE;
	}
	if (BN_cmp(signature->s, zero) != 1) {
		BN_free(zero);
		return WRONG_SIGNATURE;
	}
	BN_free(zero);

	BIGNUM* prime_p, *prime_p_sub_1, *prime_g, *pub_y;
	if (el_gamal->keys.priv != NULL) {
		prime_p = BN_dup(el_gamal->keys.priv->pub.prime_p);
		prime_g = BN_dup(el_gamal->keys.priv->pub.prime_g);
		pub_y = BN_dup(el_gamal->keys.priv->pub.pub_y);
	}
	else if (el_gamal->keys.pub != NULL) {
		prime_p = BN_dup(el_gamal->keys.pub->prime_p);
		prime_g = BN_dup(el_gamal->keys.pub->prime_g);
		pub_y = BN_dup(el_gamal->keys.pub->pub_y);
	}
	else
		return NO_KEYS;

	prime_p_sub_1 = BN_dup(prime_p);

	if (!BN_sub_word(prime_p_sub_1, 1)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on subtracting 1 to prime_p num: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_p_sub_1);
		BN_free(prime_g);
		BN_free(pub_y);

		return OPENSSL_BN_ERR;
	}
	if (BN_cmp(signature->r, prime_p) != -1) {
		BN_free(prime_p);
		BN_free(prime_p_sub_1);
		BN_free(prime_g);
		BN_free(pub_y);
		return WRONG_SIGNATURE;
	}
	if (BN_cmp(signature->s, prime_p_sub_1) != -1) {
		BN_free(prime_p);
		BN_free(prime_p_sub_1);
		BN_free(prime_g);
		BN_free(pub_y);
		return WRONG_SIGNATURE;
	}
	BN_free(prime_p_sub_1);


	BIGNUM* hash_num = BN_bin2bn(string_to_sha256(msg), SHA256_DIGEST_LENGTH, NULL);
	BIGNUM* right_side = BN_new();
	BIGNUM* r_exp_s = BN_new();
	BIGNUM* y_exp_r = BN_new();
	BIGNUM* left_side = BN_new();

	if (!BN_mod_exp(right_side, prime_g, hash_num, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_free(hash_num);
		BN_free(right_side);
		BN_free(r_exp_s);
		BN_free(y_exp_r);
		BN_free(left_side);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_exp(r_exp_s, signature->r, signature->s, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_free(hash_num);
		BN_free(right_side);
		BN_free(r_exp_s);
		BN_free(y_exp_r);
		BN_free(left_side);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_exp(y_exp_r, pub_y, signature->r, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on exponent: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_free(hash_num);
		BN_free(right_side);
		BN_free(r_exp_s);
		BN_free(y_exp_r);
		BN_free(left_side);

		return OPENSSL_BN_ERR;
	}

	if (!BN_mod_mul(left_side, r_exp_s, y_exp_r, prime_p, el_gamal->ctx)) {
		char* err_buf = new char[1024];
		ERR_error_string_n(ERR_get_error(), err_buf, 1024);
		std::cout << "Error on mod mul: \t" << err_buf << std::endl;
		delete[] err_buf;
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_free(hash_num);
		BN_free(right_side);
		BN_free(r_exp_s);
		BN_free(y_exp_r);
		BN_free(left_side);

		return OPENSSL_BN_ERR;
	}

	if (BN_cmp(left_side, right_side) == 0) {
		BN_free(prime_p);
		BN_free(prime_g);
		BN_free(pub_y);
		BN_free(hash_num);
		BN_free(right_side);
		BN_free(r_exp_s);
		BN_free(y_exp_r);
		BN_free(left_side);

		return SUCCESS;
	}


	BN_free(prime_p);
	BN_free(prime_g);
	BN_free(pub_y);
	BN_free(hash_num);
	BN_free(right_side);
	BN_free(r_exp_s);
	BN_free(y_exp_r);
	BN_free(left_side);

	return WRONG_SIGNATURE;
}