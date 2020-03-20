/*
** cert.h - digital certificates interface
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

#pragma once

#if defined(LECNET_EXPORTS)
	#include "lecnet.h"
#else
	#include <liblec/lecnet.h>
#endif

#include <string>

namespace liblec {
	namespace lecnet {
		// Correct usage of the members of liblec::lecnet::cert to make a pair of digital
		// certificates for use in a tcp server/client ssl connection is as follows:
		//
		// 1. Make CA certificate
		//
		// liblec::lecnet::cert::certificate ca_cert;
		// ca_cert.file_name = "ca.crt";
		//
		// liblec::lecnet::cert::private_key ca_key;
		// ca_key.file_name = "ca.crt";	// make it a single file
		// ca_key.password = "ca_password123";
		//
		// if (!liblec::lecnet::cert::gen_rsa_and_cert(ca_key, ca_cert)) {
		//		// error
		// }
		//
		// 2. Make Server certificate request
		//
		// liblec::lecnet::cert::certificate_request server_cert_request;
		// server_cert_request.file_name = "server.csr";
		//
		// liblec::lecnet::cert::private_key server_key;
		// server_key.file_name = "server.key";
		// server_key.password = "server_password123";
		//
		// if (!liblec::lecnet::cert::gen_rsa_and_csr(server_key, server_cert_request)) {
		//		// error
		// }
		//
		// 3. Sign the server certificate request using the CA certificate
		// (this creates the server certificate)
		//
		// if (!liblec::lecnet::cert::sign_csr("ca.crt",
		//		"ca_password123", "server.csr", "server.crt")) {
		//		// error
		// }
		//
		// 4. Append the contents of server.key to server.crt then delete server.key
		// 5. Delete the server certificate request
		//
		// The file ca.crt is used by the tcp client while server.crt together with the password
		// to the embedded server private key "server_password123" are used by the tcp server.
		//

		namespace cert {
			/// <summary>
			/// RSA private key.
			/// </summary>
			struct private_key {
				std::string file_name = "rsa.key";
				std::string password;
				unsigned short bits = 2048;
			};

			/// <summary>
			/// x509 certificate.
			/// </summary>
			struct certificate {
				std::string file_name = "cert.crt";
				unsigned short days = 365 * 3;
				std::string country = "ZW";
				std::string issuer = "liblec";
			};

			/// <summary>
			/// Certificate request.
			/// </summary>
			struct certificate_request {
				std::string file_name = "certreq.csr";
				unsigned short days = 365;
				std::string country = "ZW";
				std::string issuer = "lecnet";
			};

			/// <summary>
			/// Generate RSA key and x509 Certificate, and save them to disk.
			/// </summary>
			///
			/// <param name="key">
			/// The private key, as defined in the private_key struct. The password to this
			/// private key is required when signing a certificate request using this certificate.
			/// </param>
			///
			/// <param name="cert">
			/// The digital certificate, as defined in the certificate struct.
			/// </param>
			///
			/// <param name="error">
			/// Error information.
			/// </param>
			///
			/// <returns>
			/// Returns true if successful, else false.
			/// </returns>
			///
			/// <remarks>
			/// Key is saved to private_key.file_name and certificate is saved to
			/// certificate.file_name. If these two values are the same one file is saved,
			/// containing both.
			/// </remarks>
			bool lecnet_api gen_rsa_and_cert(const private_key& key,
				const certificate& cert,
				std::string& error);

			/// <summary>
			/// Generate RSA key and Certificate Request, and save them to disk.
			/// </summary>
			///
			/// <param name="key">
			/// The private key, as defined in the private_key struct.
			/// </param>
			///
			/// <param name="csr_req">
			/// The certificate request, as defined in the certificate_request struct.
			/// </param>
			///
			/// <param name="error">
			/// Error information.
			/// </param>
			///
			/// <returns>
			/// Returns true if successful, else false.
			/// </returns>
			///
			/// <remarks>
			/// Key is saved to private_key.file_name and certificate request is saved to
			/// certificate_request.file_name
			/// </remarks>
			bool lecnet_api gen_rsa_and_csr(const private_key& key,
				const certificate_request& csr_req,
				std::string& error);

			/// <summary>
			/// Sign Certificate Request, and save the certificate to disk.
			/// </summary>
			///
			/// <param name="ca_cert_file">
			/// CA Certificate file.
			/// </param>
			///
			/// <param name="ca_key_file">
			/// CA Certificate private key file.
			/// </param>
			///
			/// <param name="ca_key_password">
			/// CA Certificate private key password.
			/// </param>
			///
			/// <param name="csr_file">
			/// Certificate request file.
			/// </param>
			///
			/// <param name="certificate_file">
			/// The file to save the certificate to.
			/// </param>
			///
			/// <param name="days">
			/// Number of days for which certificate is valid.
			/// </param>
			///
			/// <param name="error">
			/// Error information.
			/// </param>
			///
			/// <returns>
			/// Returns true if successful, else false.
			/// </returns>
			///
			/// <remarks>
			/// After the certificate is made successfully, it is highly recommended that the
			/// <see cref="csr_file"/> file be deleted.
			/// </remarks>
			bool lecnet_api sign_csr(const std::string& ca_cert_file,
				const std::string& ca_key_file,
				const std::string& ca_key_password,
				const std::string& csr_file,
				const std::string& certificate_file,
				short days,
				std::string& error);
		}
	}
}
