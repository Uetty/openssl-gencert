/*
 * openssl_util.h
 *
 *  Created on: 2017年5月31日
 *      Author: root
 */

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_UTIL_H_
#define OPENSSL_UTIL_H_

void initialize_crypto();

void cleanup_crypto();

int open_crtfile(char* certfile, X509 **cert);

int open_csrfile(char* certfile, X509_REQ **req);

int open_keyfile(char* keyfile, EVP_PKEY **pkey);

int file_write_key(EVP_PKEY *key, char *keyfile);

int file_write_csr(X509_REQ *req, char *csrfile);

int file_write_cert(X509 *cert, char* crtfile);

int file_write_pkcs12(PKCS12 *p12, char* p12file);

int openssl_pkcs12_create(X509 *cert, EVP_PKEY *pkey, char* name, char* pass, PKCS12 **p12,
STACK_OF(X509) *ca);

int open_pkcs12(char* p12file, X509 **cert, EVP_PKEY **pkey, char* pass,
		STACK_OF(X509) **ca);

void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path,
		X509 **ca_crt);

int openssl_genrsa_key(EVP_PKEY **key, int key_size);

int openssl_req_create(X509_REQ **req, EVP_PKEY *key,
		const unsigned char* country, const unsigned char* state_or_province,
		const unsigned char* locality, const unsigned char* organization,
		const unsigned char* organization_unit,
		const unsigned char* common_name, const EVP_MD* evp_md);

int openssl_ca_create_crt(EVP_PKEY *ca_key, X509 *ca_crt, X509_REQ *req,
		X509 **crt, const long seconds, const EVP_MD* evp_md);

#endif /* OPENSSL_UTIL_H_ */

