/*
** gen_rsa_and_csr.cpp - generate rsa and csr implementation
**
** lecnet network library
** Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
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
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#undef X509_NAME

bool write_to_disk(EVP_PKEY* pkey,
	const char* ccPrivateKeyName,
	const char* ccPrivateKeyPassword,
	X509_REQ* req,
	const char* ccReqName,
	std::string& error)
{
	/* Open the PEM file for writing the key to disk. */
	BIO* pkey_file;
	pkey_file = BIO_new(BIO_s_file());

	if (pkey_file == NULL)
	{
		error = "Unable to open PEM key file for writing";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(pkey_file);
		return false;
	}
	else
	{
		if (BIO_write_filename(pkey_file, (char*)ccPrivateKeyName) <= 0)
		{
			error = "Unable to open PEM key file for writing";

			std::string error_ = openssl_error();

			if (!error_.empty())
				error += ": " + error_;

			BIO_free_all(pkey_file);
			return false;
		}
	}

	/* Write the key to disk. */
	int ret = 0;

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

		if (error_.empty())
			error += ".";
		else
			error += ": " + error_;

		BIO_free_all(pkey_file);
		return false;
	}

	/* Open the PEM file for writing the certificate to disk. */
	BIO* csr_file;
	csr_file = BIO_new(BIO_s_file());

	if (csr_file == NULL)
	{
		error = "Unable to open PEM certificate request file for writing.";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(pkey_file);
		BIO_free_all(csr_file);
		return false;
	}
	else
	{
		if (BIO_write_filename(csr_file, (char*)ccReqName) <= 0)
		{
			error = "Unable to open PEM certificate request file for writing.";

			std::string error_ = openssl_error();

			if (!error_.empty())
				error += ": " + error_;

			BIO_free_all(pkey_file);
			BIO_free_all(csr_file);
			return false;
		}
	}

	/* Write the certificate to disk. */
	ret = PEM_write_bio_X509_REQ(csr_file, req);

	if (!ret)
	{
		error = "Unable to write certificate request to disk";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		BIO_free_all(pkey_file);
		BIO_free_all(csr_file);
		return false;
	}

	BIO_free_all(pkey_file);
	BIO_free_all(csr_file);

	return true;
}

bool mkreq(X509_REQ** req,
	EVP_PKEY* pk,
	int bits,
	int serial,
	int days,
	const char* ccCountry,
	const char* ccIssuer)
{
	X509_REQ* x;
	RSA* rsa;
	X509_NAME* name = NULL;
	STACK_OF(X509_EXTENSION)* exts = NULL;

	if ((x = X509_REQ_new()) == NULL)
		return false;

	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	if (!EVP_PKEY_assign_RSA(pk, rsa))
		return false;

	rsa = NULL;

	X509_REQ_set_pubkey(x, pk);

	name = X509_REQ_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	* correct string type and performing checks on its length.
	* Normally we'd check the return value for errors...
	*/
	X509_NAME_add_entry_by_txt(name, "C",
		MBSTRING_ASC, (unsigned char*)ccCountry, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",
		MBSTRING_ASC, (unsigned char*)ccIssuer, -1, -1, 0);

	if (!X509_REQ_sign(x, pk, EVP_sha1()))
		return false;

	*req = x;

	return true;
}

bool liblec::lecnet::cert::gen_rsa_and_csr(const private_key& key,
	const certificate_request& csr_req,
	std::string& error)
{
	error.clear();

	// Initialize OpenSSL
	init_openssl();

	// Generate the key.
	EVP_PKEY* pkey = generate_key(key.bits, error);

	if (!pkey)
		return false;

	X509_REQ* req = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	// make certificate request
	bool bRes = mkreq(&req,
		pkey, 2048, 0, csr_req.days, csr_req.country.c_str(), csr_req.issuer.c_str());

	if (bRes)
	{
		// save to file
		bRes = write_to_disk(pkey,
			key.file_name.c_str(), key.password.c_str(), req, csr_req.file_name.c_str(), error);
	}
	else
		error = openssl_error();

	X509_REQ_free(req);
	EVP_PKEY_free(pkey);

	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();

	return bRes;
}
