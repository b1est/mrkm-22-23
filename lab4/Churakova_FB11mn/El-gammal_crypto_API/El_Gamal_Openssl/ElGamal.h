#pragma once
#include <string>

#include <openssl/bn.h>

enum El_Gamal_ERRs
{
	SUCCESS = 0,
	NO_KEYS,
	NO_PRIV,
	NO_PUB,
	ALREADY_INITIALIZED,
	ALREADY_GENERATED,
	SES_KEY_GEN_ERR,
	NO_CT,
	NO_SIGNATURE,
	WRONG_SIGNATURE,
	OPENSSL_BN_ERR,
	TOO_LARGE_MSG,
	OTHER_ERR,
};

struct El_Gamal_signature {
	BIGNUM* r = NULL;
	BIGNUM* s = NULL;
};

struct El_Gamal_ciphertext {
	BIGNUM* a = NULL;
	BIGNUM* b = NULL;
};

struct El_Gamal_pub {
	BN_ULONG bits_p;
	BN_ULONG bits_g;
	BIGNUM* prime_p = NULL;
	BIGNUM* prime_g = NULL;
	BIGNUM* pub_y = NULL;
};

struct El_Gamal_priv {
	El_Gamal_pub pub;
	BIGNUM* priv_x = NULL;
};

struct El_Gamal_keys {
	El_Gamal_pub *pub = NULL;
	El_Gamal_priv *priv = NULL;
};

struct El_Gamal {
	El_Gamal_keys keys;
	BN_CTX* ctx = NULL;
};

El_Gamal_signature* ElGamal_signature_init();

int ElGamal_signature_free(El_Gamal_signature*& signature);

El_Gamal_ciphertext* ElGamal_ciphertext_init();

int ElGamal_ciphertext_free(El_Gamal_ciphertext*& ct);

int ElGamal_init_priv(El_Gamal* el_gamal);

int ElGamal_init_pub(El_Gamal* el_gamal);

El_Gamal* ElGamal_init();

int ElGamal_free_priv(El_Gamal* el_gamal);

int ElGamal_free_pub(El_Gamal* el_gamal);

int ElGamal_free(El_Gamal*& el_gamal);

int ElGamal_generate_private_key(El_Gamal* el_gamal, BN_ULONG bits_p=1024, BN_ULONG bits_g=512);

int ElGamal_generate_public_key(El_Gamal* el_gamal);

int ELGamal_gen_session_key(El_Gamal* el_gamal, BIGNUM*& ses_key);

int ElGamal_encrypt(El_Gamal* el_gamal, std::string msg, El_Gamal_ciphertext*& ct);

int ElGamal_decrypt(El_Gamal* el_gamal, std::string& msg, El_Gamal_ciphertext* ct);

int ELGamal_gen_session_key_signature(El_Gamal* el_gamal, BIGNUM*& ses_key);

int ElGamal_sign(El_Gamal* el_gamal, std::string msg, El_Gamal_signature*& signature);

int ElGamal_verify(El_Gamal* el_gamal, std::string msg, El_Gamal_signature* signature);

