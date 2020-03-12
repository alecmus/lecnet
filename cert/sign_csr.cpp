/*
** sign_csr.cpp - sign csr implementation
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

// standard includes
#include <fstream>

// openssl includes
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6
#define FORMAT_ENGINE   7
#define FORMAT_IISSGC	8	/* XXX this stupid macro helps us to avoid
* adding yet another param to load_*key() */
#define FORMAT_PEMRSA	9	/* PEM RSAPubicKey format */
#define FORMAT_ASN1RSA	10	/* DER RSAPubicKey format */
#define FORMAT_MSBLOB	11	/* MS Key blob format */
#define FORMAT_PVK	12	/* MS PVK file format */

#define EXT_COPY_NONE	0
#define EXT_COPY_ADD	1
#define EXT_COPY_ALL	2

#define NETSCAPE_CERT_HDR	"certificate"

/*
** workaround for the
** #define in wincrypt.h
*/
#undef X509_NAME

std::string last_error;

static int reqfile = 0;

int pkey_ctrl_string(EVP_PKEY_CTX* ctx, char* value)
{
	int rv;
	char* stmp,* vtmp = NULL;
	stmp = BUF_strdup(value);
	if (!stmp)
		return -1;
	vtmp = strchr(stmp, ':');
	if (vtmp)
	{
		*vtmp = 0;
		vtmp++;
	}
	rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
	OPENSSL_free(stmp);
	return rv;
}

static int do_sign_init(BIO* err, EVP_MD_CTX* ctx, EVP_PKEY* pkey,
	const EVP_MD* md, STACK_OF(OPENSSL_STRING)* sigopts)
{
	EVP_PKEY_CTX* pkctx = NULL;
	int i;
	EVP_MD_CTX_init(ctx);
	if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
		return 0;
	for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++)
	{
		char* sigopt = sk_OPENSSL_STRING_value(sigopts, i);
		if (pkey_ctrl_string(pkctx, sigopt) <= 0)
		{
			last_error = "Parameter error: ";
			last_error += openssl_error();
			return 0;
		}
	}
	return 1;
}

int do_X509_sign(BIO* err, X509* x, EVP_PKEY* pkey, const EVP_MD* md,
	STACK_OF(OPENSSL_STRING)* sigopts)
{
	int rv;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);
	rv = do_sign_init(err, &mctx, pkey, md, sigopts);
	if (rv > 0)
		rv = X509_sign_ctx(x, &mctx);
	EVP_MD_CTX_cleanup(&mctx);
	return rv > 0 ? 1 : 0;
}

#undef BSIZE
#define BSIZE 256

static int x509_certify(X509_STORE* ctx, char* CAfile, const EVP_MD* digest,
	X509* x, X509* xca, EVP_PKEY* pkey,
	STACK_OF(OPENSSL_STRING)* sigopts,
	char* serialfile, int create,
	int days, int clrext, CONF* conf, char* section,
	ASN1_INTEGER* sno)
{
	int ret = 0;
	ASN1_INTEGER* bs = sno;
	X509_STORE_CTX xsc;
	EVP_PKEY* upkey;

	upkey = X509_get_pubkey(xca);
	EVP_PKEY_copy_parameters(upkey, pkey);
	EVP_PKEY_free(upkey);

	if (!X509_STORE_CTX_init(&xsc, ctx, x, NULL))
	{
		last_error = "Error initialising X509 store";
		goto end;
	}

	/*	if (!X509_STORE_add_cert(ctx,x)) goto end;*/

	/* NOTE: this certificate can/should be self signed, unless it was
	* a certificate request in which case it is not. */
	X509_STORE_CTX_set_cert(&xsc, x);
	X509_STORE_CTX_set_flags(&xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
	if (!reqfile && X509_verify_cert(&xsc) <= 0)
		goto end;

	if (!X509_check_private_key(xca, pkey))
	{
		last_error = "CA certificate and CA private key do not match";
		goto end;
	}

	if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
	{
		last_error = "Unable to set issuer name to certificate";
		goto end;
	}

	if (!X509_set_serialNumber(x, bs))
	{
		last_error = "Unable to set serial number to certificate";
		goto end;
	}

	if (X509_gmtime_adj(X509_get_notBefore(x), 0L) == NULL)
		goto end;

	/* hardwired expired */
	if (X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL) == NULL)
		goto end;

	if (clrext)
	{
		while (X509_get_ext_count(x) > 0) X509_delete_ext(x, 0);
	}

	if (!do_X509_sign(NULL, x, pkey, digest, sigopts))
		goto end;

	ret = 1;
end:
	X509_STORE_CTX_cleanup(&xsc);

	if (!ret)
		last_error = openssl_error();

	if (!sno)
		ASN1_INTEGER_free(bs);

	return ret;
}

typedef struct pw_cb_data
{
	const void* password;
	const char* prompt_info;
} PW_CB_DATA;

int password_callback(char* buf, int bufsiz, int verify,
	PW_CB_DATA* cb_tmp)
{
	UI* ui = NULL;
	int res = 0;
	const char* prompt_info = NULL;
	const char* password = NULL;
	PW_CB_DATA* cb_data = (PW_CB_DATA*)cb_tmp;

	if (cb_data)
	{
		if (cb_data->password)
			password = (char*)cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password)
	{
		res = (int)strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	return res;
}

X509* load_cert(BIO* err, const char* file, int format,
	const char* pass, ENGINE* e, const char* cert_descrip)
{
	X509* x = NULL;
	BIO* cert;

	if ((cert = BIO_new(BIO_s_file())) == NULL)
	{
		last_error = openssl_error();
		goto end;
	}

	if (file == NULL)
	{
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
		setvbuf(stdin, NULL, _IONBF, 0);
# endif /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
		BIO_set_fp(cert, stdin, BIO_NOCLOSE);
	}
	else
	{
		if (BIO_read_filename(cert, file) <= 0)
		{
			last_error = "Error opening " + std::string(file);
			goto end;
		}
	}

	if (format == FORMAT_PEM)
		x = PEM_read_bio_X509_AUX(cert, NULL,
		(pem_password_cb*)password_callback, NULL);

end:
	if (x == NULL)
	{
		last_error = "Unable to load certificate: ";
		last_error += openssl_error();
	}

	if (cert != NULL)
		BIO_free(cert);

	return(x);
}

static UI_METHOD* ui_method = NULL;

EVP_PKEY* load_key(BIO* err, const char* file, int format, int maybe_stdin,
	const char* pass, ENGINE* e, const char* key_descrip)
{
	BIO* key = NULL;
	EVP_PKEY* pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE))
	{
		last_error = "No keyfile specified";
		goto end;
	}

	key = BIO_new(BIO_s_file());

	if (key == NULL)
	{
		last_error = openssl_error();
		goto end;
	}
	if (file == NULL && maybe_stdin)
	{
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
		setvbuf(stdin, NULL, _IONBF, 0);
# endif /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
		BIO_set_fp(key, stdin, BIO_NOCLOSE);
	}
	else
		if (BIO_read_filename(key, file) <= 0)
		{
			last_error = "Error opening " + std::string(file) + ": ";
			last_error += openssl_error();
			goto end;
		}

	if (format == FORMAT_PEM)
	{
		pkey = PEM_read_bio_PrivateKey(key, NULL,
			(pem_password_cb*)password_callback, &cb_data);
	}

end:
	if (key != NULL)
		BIO_free(key);

	if (pkey == NULL)
	{
		if (file == NULL)
			last_error = "Unable to load file: ";
		else
			last_error = "Unable to load " + std::string(file) + ": ";

		last_error += openssl_error();
	}

	return(pkey);
}

// check if file exists
bool FileExists(std::string sFullPath)
{
	std::ifstream file(sFullPath.c_str(), std::ios::in);

	if (!file.is_open())
	{
		// file does not exist
		return false;
	}

	file.close();

	return true;
}

bool liblec::lecnet::cert::sign_csr(const std::string& ca_cert_file,
	const std::string& ca_key_file,
	const std::string& ca_key_password,
	const std::string& csr_file,
	const std::string& certificate_file,
	short days,
	std::string& error)
{
	error.clear();

	// initialize OpenSSL
	init_openssl();

	// local variables
	bool bRes = false;
	X509_STORE* ctx = NULL;
	X509* x509 = NULL;				// the certificate
	ASN1_INTEGER* serialNo = NULL;	// certificate's serial number
	BIO* out = NULL;
	int CAkeyformat = FORMAT_PEM;
	EVP_PKEY* CApkey = NULL;
	X509_REQ* req = NULL;
	unsigned long nmflag = 0;
	int i = 0;
	X509* xca = NULL;

	char* outfile = (char*)certificate_file.c_str();
	const EVP_MD* digest = EVP_sha1();
	int clrext = 0;
	CONF* extconf = NULL;
	char* extsect = NULL;
	STACK_OF(OPENSSL_STRING)* sigopts = sk_OPENSSL_STRING_new_null();
	int iRes = 0;

	// create X509_STORE
	ctx = X509_STORE_new();

	if (ctx == NULL)
	{
		error = "Unable to create X509_STORE structure";
		goto end;
	}

	// set X509_STORE default paths
	if (!X509_STORE_set_default_paths(ctx))
	{
		error = openssl_error();
		goto end;
	}

	//  Allocate memory for the X509 structure
	if ((x509 = X509_new()) == NULL)
	{
		error = "Unable to create X509 structure";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		goto end;
	}

	// generate random serial number
	serialNo = ASN1_INTEGER_new();

	if (!serialNo || !rand_serial(NULL, serialNo))
	{
		error = "Unable to generate random serial number";

		std::string error_ = openssl_error();

		if (!error_.empty())
			error += ": " + error_;

		goto end;
	}

	// prepare output certificate file
	if (certificate_file.empty())
	{
		error = "No certificate file specified";
		goto end;
	}

	out = BIO_new(BIO_s_file());

	if (out == NULL)
	{
		error = openssl_error();
		goto end;
	}

	if (BIO_write_filename(out, outfile) <= 0)
	{
		error = openssl_error();
		goto end;
	}

	reqfile = 1;

	if (reqfile)
	{
		EVP_PKEY* pkey;
		BIO* in;

		in = BIO_new(BIO_s_file());

		if (in == NULL)
		{
			error = openssl_error();
			goto end;
		}

		// check if Certificate request file exists
		if (!FileExists(csr_file))
		{
			// file does not exist
			error = "Specified Certificate request file '" + csr_file + "' does not exist";
			goto end;
		}

		// open certificate request file
		if (BIO_read_filename(in, csr_file.c_str()) <= 0)
		{
			error = "Error loading Certificate request from the file '" + csr_file + "': ";
			error += openssl_error();

			BIO_free(in);
			goto end;
		}

		// read certificate request from the file
		req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
		BIO_free(in);

		if (req == NULL)
		{
			error = "Error loading Certificate request from the file '" + csr_file + "': ";
			error += openssl_error();
			goto end;
		}

		if ((req->req_info == NULL) ||
			(req->req_info->pubkey == NULL) ||
			(req->req_info->pubkey->public_key == NULL) ||
			(req->req_info->pubkey->public_key->data == NULL))
		{
			error = "The certificate request appears to be corrupted.";
			error += " It does not contain a public key:\r\n";
			error += openssl_error();
			goto end;
		}

		if ((pkey = X509_REQ_get_pubkey(req)) == NULL)
		{
			error = "Error unpacking public key: ";
			error += openssl_error();
			goto end;
		}

		i = X509_REQ_verify(req, pkey);
		EVP_PKEY_free(pkey);

		if (i < 0)
		{
			error = "Signature verification error: ";
			error += openssl_error();
			goto end;
		}

		if (i == 0)
		{
			error = "Signature did not match the certificate request: ";
			error += openssl_error();
			goto end;
		}
		else
		{
			// Signature ok;
		}

		if (!X509_set_issuer_name(x509, req->req_info->subject))
		{
			error = openssl_error();
			goto end;
		}

		if (!X509_set_subject_name(x509, req->req_info->subject))
		{
			error = openssl_error();
			goto end;
		}

		X509_gmtime_adj(X509_get_notBefore(x509), 0);
		X509_time_adj_ex(X509_get_notAfter(x509), days, 0, NULL);

		pkey = X509_REQ_get_pubkey(req);
		X509_set_pubkey(x509, pkey);
		EVP_PKEY_free(pkey);
	}

	if (x509 == NULL)
	{
		error = openssl_error();
		goto end;
	}

	// check if CA Certificate file exists
	if (!FileExists(ca_cert_file))
	{
		// file does not exist
		error = "Specified CA certificate file '" + ca_cert_file + "' does not exist";
		goto end;
	}

	// load CA certificate
	xca = load_cert(NULL, ca_cert_file.c_str(), FORMAT_PEM, NULL, NULL, "CA Certificate");

	if (xca == NULL)
	{
		error = "Error loading CA certificate from the file '" + ca_cert_file + "': ";
		error += openssl_error();
		goto end;
	}

	// check if CA key file exists
	if (!FileExists(ca_key_file))
	{
		// file does not exist
		error = "Specified CA key file '" + ca_key_file + "' does not exist";
		goto end;
	}

	// load CA private key file
	CApkey = load_key(NULL, ca_key_file.c_str(), CAkeyformat, 0,
		(char*)ca_key_password.c_str(), NULL, "CA Private Key");

	if (CApkey == NULL)
	{
		error = "Error loading CA key from the file '" + ca_key_file + "': ";
		error += openssl_error();
		goto end;
	}

	last_error.clear();
	iRes = x509_certify(ctx,
		(char*)ca_cert_file.c_str(),
		digest, x509, xca, CApkey, sigopts, NULL, 1, days, clrext, extconf, extsect, serialNo);

	if (!iRes)
	{
		error = last_error;
		goto end;
	}

	// write the certificate file to disk
	if (!PEM_write_bio_X509(out, x509))
	{
		error = openssl_error();
		goto end;
	}

	// file written successfully to disk
	bRes = true;

end:
	BIO_free_all(out);
	X509_STORE_free(ctx);
	X509_free(xca);
	ASN1_INTEGER_free(serialNo);

	return bRes;
}
