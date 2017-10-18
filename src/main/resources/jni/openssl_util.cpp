/*
 * p12_parser.cpp
 *
 *  Created on: 2017年5月23日
 *      Author: root
 */

#include <openssl/err.h>
#include <openssl/conf.h>

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <string>
#include <iostream>
using namespace std;

//#define RSA_KEY_BITS (2048)

#define REQ_DN_C "CN"
#define REQ_DN_ST "FJ"
#define REQ_DN_L "FZ"
#define REQ_DN_O "lanhaitianwang"
#define REQ_DN_OU "lanhaitianwang"
#define REQ_DN_CN "10.1.1.12"

void initialize_crypto() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	CRYPTO_malloc_debug_init()
	;
	CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}

void cleanup_crypto() {
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	CRYPTO_mem_leaks_fp(stderr);
}

int open_crtfile(char* certfile, X509 **cert) {
	FILE *fp;
	if ((fp = fopen(certfile, "r")) == NULL) {
		fprintf(stderr, "Error opening file %s\n", certfile);
		return 1;
	}
	*cert = PEM_read_X509(fp, NULL, 0, NULL);
	fclose(fp);
	return 0;
}

int open_csrfile(char* certfile, X509_REQ **req) {
	FILE *fp;
	if ((fp = fopen(certfile, "r")) == NULL) {
		printf("Error opening file %s\n", certfile);
		return 1;
	}
	*req = PEM_read_X509_REQ(fp, NULL, 0, NULL);
	fclose(fp);
	return 0;
}

int open_keyfile(char* keyfile, EVP_PKEY **pkey) {
	FILE *fp;
	if ((fp = fopen(keyfile, "r")) == NULL) {
		printf("Error opening file %s\n", keyfile);
		return 1;
	}
	*pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
	fclose(fp);
	return 0;
}

int file_write_key(EVP_PKEY *key, char *keyfile) {
	FILE *fp;
	if ((fp = fopen(keyfile, "w")) == NULL) {
		fprintf(stderr, "Error opening file %s\n", keyfile);
		return 1;
	}
	PEM_write_PrivateKey(fp, key, NULL, NULL, NULL, NULL, NULL);

	fclose(fp);
	return 0;
}

int file_write_csr(X509_REQ *req, char *csrfile) {
	FILE *fp;
	if ((fp = fopen(csrfile, "w")) == NULL) {
		fprintf(stderr, "Error opening file %s\n", csrfile);
		return 1;
	}
	PEM_write_X509_REQ(fp, req);

	fclose(fp);
	return 0;
}

int file_write_cert(X509 *cert, char* crtfile) {
	FILE *fp;
	if ((fp = fopen(crtfile, "w")) == NULL) {
		fprintf(stderr, "Error opening file %s\n", crtfile);
		return 1;
	}
	unsigned long f = XN_FLAG_COMPAT;
	X509_print_ex_fp(fp, cert, f, f);
	//	cout << "crtfile EX" << X509_print_fp(fp, cert) << endl;
	PEM_write_X509(fp, cert);
	fclose(fp);
	return 0;
}

int file_write_pkcs12(PKCS12 *p12, char* p12file) {
	FILE *fp;
	if ((fp = fopen(p12file, "wb")) == NULL) {
		fprintf(stderr, "Error opening file %s\n", p12file);
		return 1;
	}
	i2d_PKCS12_fp(fp, p12);
	fclose(fp);
	return 0;
}

int add_extCert(X509 *cert, X509 * root, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	//  X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, root, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 1;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 0;
}

int openssl_pkcs12_create(X509 *cert, EVP_PKEY *pkey,char *name, char* pass, PKCS12 **p12,
STACK_OF(X509) *ca) {
	//	initialize_crypto();

//	*p12 = PKCS12_create(pass, NULL, pkey, cert, NULL,
//	NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
//	NID_pbe_WithSHA1And40BitRC2_CBC, PKCS12_DEFAULT_ITER, -1, KEY_EX);
	*p12 = PKCS12_create(pass, name, pkey, cert, NULL, NULL,
			NULL, PKCS12_DEFAULT_ITER, -1, KEY_EX);
	if (!*p12) {
		fprintf(stderr, "Error creating PKCS#12 structure\n");
		return 1;
	}
	return 0;
}

int open_pkcs12(char* p12file, X509 **cert, EVP_PKEY **pkey, char* pass,
		STACK_OF(X509) **ca) {
	FILE *fp;
	if ((fp = fopen(p12file, "rb")) == NULL) {
		ERR_print_errors_fp(stderr);
		return 1;
	}
	PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12) {
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (!PKCS12_parse(p12, pass, pkey, cert, ca)) {
		ERR_print_errors_fp(stderr);
		return 1;
	}
	PKCS12_free(p12);
	return 0;
}

void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size) {
	/* Convert private key to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t *) malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path,
		X509 **ca_crt) {
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());

	if (!BIO_read_filename(bio, ca_crt_path))
		goto err;
	// get crt
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	if (!*ca_crt)
		goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());

	if (!BIO_read_filename(bio, ca_key_path))
		goto err;
	// get key
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

	if (!ca_key)
		goto err;

	BIO_free_all(bio);
	return 0;
	err: BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 1;
}

int openssl_genrsa_key(EVP_PKEY **key, int key_size) {
	*key = EVP_PKEY_new();

	if (!*key)
		goto err;
	RSA *rsa;
	rsa = RSA_generate_key(key_size, RSA_F4, NULL, NULL);

	if (!EVP_PKEY_assign_RSA(*key, rsa))
		goto err;

	return 0;
	err: EVP_PKEY_free(*key);
	return 1;
}

/**
 * const EVP_MD *EVP_md_null(void);
 #ifndef OPENSSL_NO_MD2
 const EVP_MD *EVP_md2(void);
 #endif
 #ifndef OPENSSL_NO_MD4
 const EVP_MD *EVP_md4(void);
 #endif
 #ifndef OPENSSL_NO_MD5
 const EVP_MD *EVP_md5(void);
 #endif
 #ifndef OPENSSL_NO_SHA
 const EVP_MD *EVP_sha(void);
 const EVP_MD *EVP_sha1(void);
 const EVP_MD *EVP_dss(void);
 const EVP_MD *EVP_dss1(void);
 const EVP_MD *EVP_ecdsa(void);
 #endif
 #ifndef OPENSSL_NO_SHA256
 const EVP_MD *EVP_sha224(void);
 const EVP_MD *EVP_sha256(void);
 #endif
 #ifndef OPENSSL_NO_SHA512
 const EVP_MD *EVP_sha384(void);
 const EVP_MD *EVP_sha512(void);
 #endif
 #ifndef OPENSSL_NO_MDC2
 const EVP_MD *EVP_mdc2(void);
 #endif
 #ifndef OPENSSL_NO_RIPEMD
 const EVP_MD *EVP_ripemd160(void);
 #endif
 #ifndef OPENSSL_NO_WHIRLPOOL
 const EVP_MD *EVP_whirlpool(void);
 #endif
 */
int openssl_req_create(X509_REQ **req, EVP_PKEY *key,
		const unsigned char* country, const unsigned char* state_or_province,
		const unsigned char* locality, const unsigned char* organization,
		const unsigned char* organization_unit,
		const unsigned char* common_name, const EVP_MD* evp_md) {
	*req = X509_REQ_new();

	X509_REQ_set_pubkey(*req, key);
	X509_NAME *name;
	/* Set the DN of the request. */
	name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, state_or_province, -1,
			-1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, locality, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, organization, -1, -1,
			0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, organization_unit, -1,
			-1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1,
			0);
	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, key, evp_md))
		goto err;
	return 0;
	err: EVP_PKEY_free(key);
	X509_REQ_free(*req);
	return 1;
}

int crt_set_serial_number(X509 *crt) {
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1)
		return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

int openssl_ca_create_crt(EVP_PKEY *ca_key, X509 *ca_crt, X509_REQ *req,
		X509 **crt, const long seconds, const EVP_MD *evp_md) {
	*crt = X509_new();
	if (!*crt)
		goto err;
	X509_set_version(*crt, 2); /* Set version to X509v3 */

	if (!crt_set_serial_number(*crt))
		goto err;

	/* Set issuer to CA's subject. */
	if (!X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt))) {
		printf("create_ca_signed_crt, set issuer failed!");
		goto err;
	}

	/* Set validity of certificate to 2 years. */
	if (X509_gmtime_adj(X509_get_notBefore(*crt), 0) == NULL) {
		printf("create_ca_signed_crt, set cert begin time failed!");
		goto err;
	}

	if (X509_gmtime_adj(X509_get_notAfter(*crt), seconds) == NULL) {
		printf("create_ca_signed_crt, set cert expired time failed!");
		goto err;
	}

	EVP_PKEY *req_pubkey;
	req_pubkey = X509_REQ_get_pubkey(req);
	if (!X509_set_pubkey(*crt, req_pubkey)) {
		printf("create_ca_signed_crt, set pubkey failed!");
		goto err;
	}
	EVP_PKEY_free(req_pubkey);
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */

	add_extCert(*crt, ca_crt, NID_basic_constraints, "CA:FALSE");
	add_extCert(*crt, ca_crt, NID_netscape_comment,
			"OpenSSL Generated Certificate");
	add_extCert(*crt, ca_crt, NID_subject_key_identifier, "hash");
	add_extCert(*crt, ca_crt, NID_authority_key_identifier, "keyid");

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, evp_md) == 0)
		goto err;

	return 0;
	err: X509_REQ_free(req);
	X509_free(*crt);
	return 1;
}

//int main(int argc, char **argv) {
//	char* ca_key_path = "/etc/pki/CA/private/cakey.pem";
//	char* ca_crt_path = "/etc/pki/CA/ca.crt";
//
//	char* p12_path = "/etc/pki/CA/client111.p12";
//	char* key_path = "/etc/pki/CA/client111.key";
//	char* csr_path = "/etc/pki/CA/client111.csr";
//	char* crt_path = "/etc/pki/CA/client111.crt";
//
//	initialize_crypto();
//
//	EVP_PKEY* key;
//    /* openssl genrsa -out kehuduan.key 1024 */
//	cout << "openssl genrsa " << openssl_genrsa_key(&key, 1024)
//			<< endl;
//	cout << "create key file " << file_write_key(key, key_path) << endl;
//
//    /* openssl req -new -key kehuduan.key -out kehuduan.csr */
//	X509_REQ* req = NULL;
//	cout << "openssl req "
//			<< openssl_req_create(&req, key, REQ_DN_C, REQ_DN_ST, REQ_DN_L,
//			REQ_DN_O, REQ_DN_OU, REQ_DN_CN, EVP_sha256()) << endl;
//	cout << "create csr file " << file_write_csr(req, csr_path) << endl;
//
//	/* openssl ca -in kehuduan.csr -out kehuduan.crt -days 3650 */
//	EVP_PKEY *ca_key;
//	X509* ca_crt;
//	cout << "load ca " << load_ca(ca_key_path, &ca_key, ca_crt_path, &ca_crt)
//			<< endl;
//	X509* crt;
//	cout << "openssl ca "
//			<< openssl_ca_create_crt(ca_key, ca_crt, req, &crt,
//					10 * 365 * 86400) << endl;
//	cout << "create crt file " << file_write_cert(crt, crt_path) << endl;
//
//	/* openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12 */
//	PKCS12* p12;
//	STACK_OF(X509) *ca = NULL;
//	cout << "openssl pkcs12 " << openssl_pkcs12_create(crt, key, "", &p12, ca)
//			<< endl;
//	cout << "create p12 file " << file_write_pkcs12(p12, p12_path) << endl;
//
//	EVP_PKEY_free(key);
//
//	EVP_PKEY_free(ca_key);
//	X509_free(ca_crt);
//
//	X509_REQ_free(req);
//
//	X509_free(crt);
//
//	PKCS12_free(p12);
//	free(ca);
//
//	cleanup_crypto();
//	cout << "end " << endl;
//
//	return 0;
//}

//int main(){
//	char* csr_path = "/etc/pki/CA/client111.csr";
//	X509_REQ* req;
//	initialize_crypto();
//	open_csrfile(csr_path, &req);
//	X509_REQ_free(req);
//	cleanup_crypto();
//}
