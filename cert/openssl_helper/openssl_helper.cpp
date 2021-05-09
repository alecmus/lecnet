//
// openssl_helper.cpp - openssl helper implementation
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the CC-BY-NC 2.0 license. For full details see the file
// LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
//

#include "openssl_helper.h"

// openssl includes
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#define SERIAL_RAND_BITS	64

// initialize OpenSSL
void init_openssl()
{
	CRYPTO_malloc_init();
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
} // init_openssl

// get OpenSSL error
std::string openssl_error()
{
	unsigned long err = ERR_peek_last_error();
	char buf[256];
	ERR_error_string(err, buf);

	std::string s(buf);

	return s;
} // openssl_error

// Generates a 2048-bit RSA key
EVP_PKEY* generate_key(int bits,
	std::string& error)
{
	/* Allocate memory for the EVP_PKEY structure. */
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (!pkey)
	{
		error = "Unable to create EVP_PKEY structure";

		std::string error_ = openssl_error();

		if (error_.empty())
			error += ".";
		else
			error += ": " + error_;

		return NULL;
	}

	/* Generate the RSA key and assign it to pkey. */
	RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pkey, rsa))
	{
		error = "Unable to generate 2048-bit RSA key";

		std::string error_ = openssl_error();

		if (error_.empty())
			error += ".";
		else
			error += ": " + error_;

		EVP_PKEY_free(pkey);
		return NULL;
	}

	/* The key has been generated, return it. */
	return pkey;
} // generate_key

// generate random serial
int rand_serial(BIGNUM* b,
	ASN1_INTEGER* ai)
{
	BIGNUM* btmp;
	int ret = 0;
	if (b)
		btmp = b;
	else
		btmp = BN_new();

	if (!btmp)
		return 0;

	if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
		goto error;
	if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
		goto error;

	ret = 1;

error:

	if (!b)
		BN_free(btmp);

	return ret;
} // rand_serial
