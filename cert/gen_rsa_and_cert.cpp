/*
** gen_rsa_and_cert.cpp - generate rsa and certificate implementation
**
** lecnet network library
** Copyright (c) 2018 Alec T. Musasa (alecmus at live dot com)
**
*******************************************************************************
** This file is part of the liblec library which is released under the Creative
** Commons Attribution Non-Commercial 2.0 license (CC-BY-NC 2.0). See the file
** LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
** for full license details.
*/

#include "../cert.h"
#include "openssl_helper/openssl_helper.h"

// openssl includes
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERIAL_RAND_BITS	64

/*
** workaround for the
** #define in wincrypt.h
*/
#undef X509_NAME

/* Generates a self-signed x509 certificate. */
X509* generate_x509(EVP_PKEY* pkey,
	int days,
	const char* ccCountry,
	const char* ccIssuer,
	std::string & error)
{
	/* Allocate memory for the X509 structure. */
	X509* x509 = X509_new();
	if (!x509)
	{
		error = "Unable to create X509 structure";

		std::string error_ = openssl_error();

		if (error_.empty())
			error += ".";
		else
			error += ": " + error_;

		return NULL;
	}

	// generate random serial number
	ASN1_INTEGER* serialNo = ASN1_INTEGER_new();

	if (!serialNo || !rand_serial(NULL, serialNo))
	{
		error = "Unable to generate random serial number";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		return NULL;
	}

	/* Set the serial number. */
	if (!X509_set_serialNumber(x509, serialNo))
	{
		error = "Unable to set serial number to certificate";

		ASN1_INTEGER_free(serialNo);
		return NULL;
	}

	ASN1_INTEGER_free(serialNo);

	/* This certificate is valid from now until exactly one year from now. */
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * days);

	/* Set the public key for our certificate. */
	X509_set_pubkey(x509, pkey);

	/* We want to copy the subject name to the issuer name. */
	X509_NAME* name = X509_get_subject_name(x509);

	/* Set the country code and common name. */
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)ccCountry, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)ccIssuer, -1, -1, 0);

	/* Now set the issuer name. */
	X509_set_issuer_name(x509, name);

	/* Actually sign the certificate with our key. */
	if (!X509_sign(x509, pkey, EVP_sha1()))
	{
		error = "Error signing certificate";

		std::string error_ = openssl_error();

		if (error_.empty())
			error += ".";
		else
			error += ": " + error_;

		X509_free(x509);
		return NULL;
	}

	return x509;
}

bool write_to_disk(EVP_PKEY* pkey,
	const char* ccPrivateKeyName,
	const char* ccPrivateKeyPassword,
	X509* x509,
	const char* ccCertName,
	std::string& error)
{
	/* Open the PEM file for writing the certificate to disk. */
	BIO* x509_file = NULL;
	x509_file = BIO_new(BIO_s_file());

	if (x509_file == NULL)
	{
		error = "Unable to open PEM certificate file for writing";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(x509_file);
		return false;
	}
	else
	{
		if (BIO_write_filename(x509_file, (char*)ccCertName) <= 0)
		{
			error = "Unable to open PEM certificate file for writing";

			std::string error_ = openssl_error();

			if (!error_.empty())
				error += ": " + error_;

			BIO_free_all(x509_file);
			return false;
		}
	}

	/* Write the certificate to disk. */
	if (!PEM_write_bio_X509(x509_file, x509))
	{
		error = "Unable to write certificate to disk";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(x509_file);
		return false;
	}

	/* Open the PEM file for writing the key to disk. */
	BIO* pkey_file = NULL;

	if (strcmp(ccPrivateKeyName, ccCertName))
		pkey_file = BIO_new_file(ccPrivateKeyName, "wb");
	else
		pkey_file = BIO_new_file(ccPrivateKeyName, "ab");

	if (!pkey_file)
	{
		error = "Unable to open PEM key file for writing.";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(x509_file);
		BIO_free_all(pkey_file);
		return false;
	}

	int ret = 0;

	/* Write the key to disk. */
	if (strlen(ccPrivateKeyPassword) > 0)
	{
		// DES-EDE3-CBC
		ret = PEM_write_bio_PrivateKey(pkey_file, pkey, EVP_des_ede3_cbc(),
			(unsigned char*)ccPrivateKeyPassword, (int)strlen(ccPrivateKeyPassword), NULL, NULL);
	}
	else
		ret = PEM_write_bio_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);

	if (!ret)
	{
		error = "Unable to write private key to disk";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(x509_file);
		BIO_free_all(pkey_file);
		return false;
	}

	BIO_free_all(x509_file);
	BIO_free_all(pkey_file);

	return true;
}

bool liblec::lecnet::cert::gen_rsa_and_cert(const private_key& key,
	const certificate& cert,
	std::string& error)
{
	error.clear();

	// Initialize OpenSSL
	init_openssl();

	// Generate the key.
	EVP_PKEY* pkey = generate_key(key.bits, error);

	if (!pkey)
		return false;

	// Generate the certificate.
	X509* x509 = generate_x509(pkey,
		cert.days, cert.country.c_str(), cert.issuer.c_str(), error);

	if (!x509)
	{
		EVP_PKEY_free(pkey);
		return false;
	}

	// Write the private key and certificate out to disk.
	bool ret = write_to_disk(pkey,
		key.file_name.c_str(), key.password.c_str(), x509, cert.file_name.c_str(), error);

	EVP_PKEY_free(pkey);
	X509_free(x509);

	if (ret)
		return true;
	else
		return false;
}
