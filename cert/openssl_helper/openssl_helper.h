//
// openssl_helper.h - openssl helper interface
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the CC-BY-NC 2.0 license. For full details see the file
// LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
//

#pragma once

#include <string>
#include <openssl/evp.h>

// initialize OpenSSL
void init_openssl();

// get OpenSSL error
std::string openssl_error();

// Generates a 2048-bit RSA key
EVP_PKEY* generate_key(int bits,
	std::string& error);

// generate random serial
int rand_serial(BIGNUM* b,
	ASN1_INTEGER* ai);
