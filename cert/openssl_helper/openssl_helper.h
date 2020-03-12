/*
** lecnet network library
**
** Copyright (c) 2019 Alec T. Musasa (alecmus@live.com)
**
** This code may not be copied, modified or distributed without the
** express written permission of the author. Any violation shall
** be prosecuted to the maximum extent possible under law.
**
*************************************************************************
** OpenSSL helper header file
*/

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
