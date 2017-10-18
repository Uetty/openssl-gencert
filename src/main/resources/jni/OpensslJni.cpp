/*
 * OpensslJni.cpp
 *
 *  Created on: 2017年5月31日
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
#include "string.h"

#include "jni.h"
#include "com_lhtw_openssl_OpensslUtils.h"
#include "openssl_util.h"

__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");

using namespace std;


char* jstring2Cstring(JNIEnv* env, jstring jstr)
{
	char* rtn = NULL;
	jclass clsstring = env->FindClass("java/lang/String");
	jstring strencode = env->NewStringUTF("utf-8");
	jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
	jbyteArray barr= (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
	jsize alen = env->GetArrayLength(barr);
	jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
	if (alen > 0)
	{
		rtn = (char*)malloc(alen + 1);

		memcpy(rtn, ba, alen);
		rtn[alen] = 0;
	}
	env->ReleaseByteArrayElements(barr, ba, 0);
	return rtn;
}

jstring cstring2Jstring(JNIEnv* env, char* pat)
{
	jclass strClass = env->FindClass("Ljava/lang/String;");
	jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
	jbyteArray bytes = env->NewByteArray(strlen(pat));
	env->SetByteArrayRegion(bytes, 0, strlen(pat), (jbyte*)pat);
	jstring encoding = env->NewStringUTF("utf-8");
	return (jstring)env->NewObject(strClass, ctorID, bytes, encoding);
}


JNIEXPORT jstring JNICALL Java_com_lhtw_openssl_OpensslUtils_getPrivateKey
  (JNIEnv *env, jobject jo, jstring keyPath)
{
	EVP_PKEY *pkey;
	uint8_t *key_bytes;
	size_t key_size = 0;
	initialize_crypto();
	char* key;
	char* keyPathC = jstring2Cstring(env, keyPath);
	if(open_keyfile(keyPathC, &pkey))
	{
		goto err;
	}
	key_to_pem(pkey, &key_bytes, &key_size);
	key = key_bytes;
	free(key_bytes);
	free(keyPathC);
	EVP_PKEY_free(pkey);
	cleanup_crypto();
	return cstring2Jstring(env, key);
	err:
		free(key_bytes);
		free(keyPathC);
		EVP_PKEY_free(pkey);
		cleanup_crypto();
		return NULL;
}


JNIEXPORT jstring JNICALL Java_com_lhtw_openssl_OpensslUtils_getPublicKey
  (JNIEnv *env, jobject jo, jstring keyPath)
{
	X509 *crt;
	uint8_t *crt_bytes;
	size_t crt_size = 0;
	char* key;
	initialize_crypto();
	char* keyPathC = jstring2Cstring(env, keyPath);
	if(open_crtfile(keyPathC, &crt))
	{
		goto err;
	}
	crt_to_pem(crt, &crt_bytes, &crt_size);
	key = crt_bytes;
	free(crt_bytes);
	X509_free(crt);
	cleanup_crypto();
	return cstring2Jstring(env, key);
	err:
		free(crt_bytes);
		X509_free(crt);
		cleanup_crypto();
		return NULL;
}

JNIEXPORT jint JNICALL Java_com_lhtw_openssl_OpensslUtils_opensslGenrsa
  (JNIEnv *env, jobject jo, jint keySize,jstring keyPath)
{
	EVP_PKEY *pkey;
	char* keyPathC = jstring2Cstring(env, keyPath);

	initialize_crypto();

	if(openssl_genrsa_key(&pkey, keySize))
	{
		goto err;
	}

	if(file_write_key(pkey, keyPathC))
	{
		goto err;
	}

	free(keyPathC);
	EVP_PKEY_free(pkey);
	cleanup_crypto();
	return 0;
	err:
		free(keyPathC);
		EVP_PKEY_free(pkey);
		cleanup_crypto();
		return 1;
}

EVP_MD* get_evp_md(int evpMode)
{
	switch(evpMode){
		case 1:
			return EVP_sha1();
		case 2:
			return EVP_md2();
		case 4:
			return EVP_md4();
		case 5:
			return EVP_md5();
		case 224:
			return EVP_sha224();
		case 256:
			return EVP_sha256();
		case 384:
			return EVP_sha384();
		case 512:
			return EVP_sha512();
		}
	return EVP_sha256();
}

JNIEXPORT jint JNICALL Java_com_lhtw_openssl_OpensslUtils_opensslReq
  (JNIEnv *env, jobject jo, jstring keyFile, jint evpMode, jstring country, jstring stateOrProvince,
		  jstring locality, jstring orgName, jstring orgUnitName, jstring commonName, jstring csrPath)
{
	char* keyFileC = jstring2Cstring(env, keyFile);
	const unsigned char* cC = jstring2Cstring(env, country);
	const unsigned char* stC = jstring2Cstring(env, stateOrProvince);
	const unsigned char* lC = jstring2Cstring(env, locality);
	const unsigned char* oC = jstring2Cstring(env, orgName);
	const unsigned char* ouC = jstring2Cstring(env, orgUnitName);
	const unsigned char* cnC = jstring2Cstring(env, commonName);
	char* csrPathC = jstring2Cstring(env, csrPath);

	EVP_PKEY *pkey;
	X509_REQ* req = NULL;
	const EVP_MD* evp_md = get_evp_md(evpMode);


	initialize_crypto();
	if(open_keyfile(keyFileC, &pkey))
	{
		goto err;
	}

	if(openssl_req_create(&req, pkey, cC, stC, lC, oC, ouC, cnC, evp_md))
	{
		goto err;
	}

	if(file_write_csr(req, csrPathC)){
		goto err;
	}

	free(keyFileC);
	free(csrPathC);
	EVP_PKEY_free(pkey);
	X509_REQ_free(req);

	cleanup_crypto();
	return 0;
	err:
		free(keyFileC);
		free(csrPathC);
//		free(cC);
//		free(stC);
//		free(lC);
//		free(oC);
//		free(ouC);
//		free(cnC);
//		free(csrPathC);
		EVP_PKEY_free(pkey);
		X509_REQ_free(req);
		cleanup_crypto();
		return 1;
}

JNIEXPORT jint JNICALL Java_com_lhtw_openssl_OpensslUtils_opensslCa
  (JNIEnv *env, jobject jo, jstring caKeyFile, jstring caCrtFile, jstring csrFile, jlong term, jstring crtPath,jint evpMode)
{
	char* caKeyFileC = jstring2Cstring(env, caKeyFile);
	char* caCrtFileC = jstring2Cstring(env, caCrtFile);
	char* csrFileC = jstring2Cstring(env, csrFile);
	char* crtPathC = jstring2Cstring(env, crtPath);

	EVP_PKEY *caKey;
	X509 *caCrt;
	X509_REQ *req;
	X509 *crt;
	const EVP_MD* evp_md = get_evp_md(evpMode);

	initialize_crypto();

	if(load_ca(caKeyFileC, &caKey, caCrtFileC, &caCrt)){
		goto err;
	}
	free(caKeyFileC);
	free(caCrtFileC);

	if(open_csrfile(csrFileC, &req)){
		goto err;
	}
	free(csrFileC);

	if(openssl_ca_create_crt(caKey, caCrt, req, &crt, term, evp_md)){
		goto err;
	}

	if(file_write_cert(crt, crtPathC)){
		goto err;
	}
	free(crtPathC);

	EVP_PKEY_free(caKey);
	X509_free(caCrt);
	X509_free(crt);
	X509_REQ_free(req);
	cleanup_crypto();
	return 0;
	err:
		free(caKeyFileC);
		free(caCrtFileC);
		free(csrFileC);
		free(crtPathC);
		EVP_PKEY_free(caKey);
		X509_free(caCrt);
		X509_free(crt);
		X509_REQ_free(req);
		cleanup_crypto();
		return 1;
}

JNIEXPORT jint JNICALL Java_com_lhtw_openssl_OpensslUtils_opensslPkcs12
  (JNIEnv *env, jobject jo, jstring keyFile, jstring crtFile, jstring name, jstring pass, jstring p12Path)
{
	char* keyFileC = jstring2Cstring(env, keyFile);
	char* crtFileC = jstring2Cstring(env, crtFile);
	char* passC = jstring2Cstring(env, pass);
	char* nameC = jstring2Cstring(env, name);
	char* p12PathC = jstring2Cstring(env, p12Path);

	EVP_PKEY *key;
	X509 *cert;
	PKCS12 *p12;
	STACK_OF(X509) *stof;

	initialize_crypto();

	if(open_keyfile(keyFileC, &key))
	{
		goto err;
	}
	if(open_crtfile(crtFileC, &cert))
	{
		goto err;
	}

	if(openssl_pkcs12_create(cert, key, nameC, passC, &p12, stof))
	{
		goto err;
	}

	if(file_write_pkcs12(p12, p12PathC)){
		goto err;
	}

	free(keyFileC);
	free(crtFileC);
	free(passC);
	free(nameC);
	free(p12PathC);
	EVP_PKEY_free(key);
	X509_free(cert);
	PKCS12_free(p12);
	cleanup_crypto();
	return 0;
	err:
		free(keyFileC);
		free(crtFileC);
		free(passC);
		free(nameC);
		free(p12PathC);
		EVP_PKEY_free(key);
		X509_free(cert);
		PKCS12_free(p12);
		cleanup_crypto();
		return 1;
}

JNIEXPORT jint JNICALL Java_com_lhtw_openssl_OpensslUtils_createClientCertificateP12
  (JNIEnv *env, jobject jo, jint keySize, jstring keyPath, jint evpMode, jstring country, jstring stateOrProvince, jstring locality, jstring orgName,
		  jstring orgUnitName, jstring commonName, jstring csrPath, jstring caKeyFile, jstring caCrtFile, jlong term, jstring crtPath,jstring name, jstring pass, jstring p12Path)
{
	initialize_crypto();

	EVP_PKEY *pkey;
	char* keyPathC = jstring2Cstring(env, keyPath);

	unsigned char* cC;
	unsigned char* stC;
	unsigned char* lC;
	unsigned char* oC;
	unsigned char* ouC;
	unsigned char* cnC;
	char* csrPathC;
	const EVP_MD* evp_md = get_evp_md(evpMode);
	X509_REQ* req = NULL;

	char* caKeyFileC;
	char* caCrtFileC;
	char* crtPathC;
	EVP_PKEY *caKey;
	X509 *caCrt;
	X509 *crt;

	char* nameC;
	char* passC;
	char* p12PathC;
	PKCS12 *p12;
	STACK_OF(X509) *stof;

	// openssl genrsa

	if(openssl_genrsa_key(&pkey, keySize))
	{
		goto generr;
	}
	if(file_write_key(pkey, keyPathC))
	{
		goto generr;
	}

	// openssl req
	cC = jstring2Cstring(env, country);
	stC = jstring2Cstring(env, stateOrProvince);
	lC = jstring2Cstring(env, locality);
	oC = jstring2Cstring(env, orgName);
	ouC = jstring2Cstring(env, orgUnitName);
	cnC = jstring2Cstring(env, commonName);
	csrPathC = jstring2Cstring(env, csrPath);

	if(openssl_req_create(&req, pkey, cC, stC, lC, oC, ouC, cnC, evp_md))
	{
		goto reqerr;
	}
	if(file_write_csr(req, csrPathC)){
		goto reqerr;
	}


	//openssl ca
	caKeyFileC = jstring2Cstring(env, caKeyFile);
	caCrtFileC = jstring2Cstring(env, caCrtFile);
	crtPathC = jstring2Cstring(env, crtPath);

	if(load_ca(caKeyFileC, &caKey, caCrtFileC, &caCrt)){
		goto loadcaerr;
	}
	if(openssl_ca_create_crt(caKey, caCrt, req, &crt, term, evp_md)){
		goto caerr;
	}
	if(file_write_cert(crt, crtPathC)){
		goto caerr;
	}

	//openssl pkcs12

	passC = jstring2Cstring(env, pass);
	nameC = jstring2Cstring(env, name);
	p12PathC = jstring2Cstring(env, p12Path);

	if(openssl_pkcs12_create(crt, pkey, nameC, passC, &p12, stof))
	{
		goto pkcs12err;
	}

	if(file_write_pkcs12(p12, p12PathC)){
		goto pkcs12err;
	}



	PKCS12_free(p12);
	X509_free(crt);
	EVP_PKEY_free(caKey);
	X509_free(caCrt);
	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
	cleanup_crypto();
	free(passC);
	free(nameC);
	free(p12PathC);
	free(caKeyFileC);
	free(caCrtFileC);
	free(crtPathC);
	free(csrPathC);
	free(keyPathC);
	free(cC);
	free(stC);
	free(lC);
	free(oC);
	free(ouC);
	free(cnC);
	return 0;
	generr:
		EVP_PKEY_free(pkey);
		cleanup_crypto();
		free(keyPathC);
		return 1;
	reqerr:
		EVP_PKEY_free(pkey);
		X509_REQ_free(req);
		cleanup_crypto();
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		return 2;
	loadcaerr:
		EVP_PKEY_free(caKey);
		X509_free(caCrt);
		X509_REQ_free(req);
		EVP_PKEY_free(pkey);
		cleanup_crypto();
		free(caKeyFileC);
		free(caCrtFileC);
		free(crtPathC);
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		return 3;
	caerr:
		X509_free(crt);
		EVP_PKEY_free(caKey);
		X509_free(caCrt);
		X509_REQ_free(req);
		EVP_PKEY_free(pkey);
		cleanup_crypto();
		free(caKeyFileC);
		free(caCrtFileC);
		free(crtPathC);
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		return 4;
	pkcs12err:
		PKCS12_free(p12);
		EVP_PKEY_free(pkey);
		X509_REQ_free(req);
		EVP_PKEY_free(caKey);
		X509_free(caCrt);
		X509_free(crt);
		cleanup_crypto();
		free(passC);
		free(nameC);
		free(p12PathC);
		free(caKeyFileC);
		free(caCrtFileC);
		free(crtPathC);
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		return 5;
}

JNIEXPORT jint JNICALL Java_com_lhtw_openssl_OpensslUtils_createClientCertificateCrt
  (JNIEnv *env, jobject jo, jint keySize, jstring keyPath, jint evpMode, jstring country, jstring stateOrProvince, jstring locality, jstring orgName,
		  jstring orgUnitName, jstring commonName, jstring csrPath, jstring caKeyFile, jstring caCrtFile, jlong term, jstring crtPath)
{
	initialize_crypto();

	EVP_PKEY *pkey;
	char* keyPathC = jstring2Cstring(env, keyPath);

	unsigned char* cC;
	unsigned char* stC;
	unsigned char* lC;
	unsigned char* oC;
	unsigned char* ouC;
	unsigned char* cnC;
	char* csrPathC;
	const EVP_MD* evp_md = get_evp_md(evpMode);
	X509_REQ* req = NULL;

	char* caKeyFileC;
	char* caCrtFileC;
	char* crtPathC;
	EVP_PKEY *caKey;
	X509 *caCrt;
	X509 *crt;

	// openssl genrsa

	if(openssl_genrsa_key(&pkey, keySize))
	{
		goto generr;
	}
	if(file_write_key(pkey, keyPathC))
	{
		goto generr;
	}

	// openssl req
	cC = jstring2Cstring(env, country);
	stC = jstring2Cstring(env, stateOrProvince);
	lC = jstring2Cstring(env, locality);
	oC = jstring2Cstring(env, orgName);
	ouC = jstring2Cstring(env, orgUnitName);
	cnC = jstring2Cstring(env, commonName);
	csrPathC = jstring2Cstring(env, csrPath);

	if(openssl_req_create(&req, pkey, cC, stC, lC, oC, ouC, cnC, evp_md))
	{
		goto reqerr;
	}
	if(file_write_csr(req, csrPathC)){
		goto reqerr;
	}


	//openssl ca
	caKeyFileC = jstring2Cstring(env, caKeyFile);
	caCrtFileC = jstring2Cstring(env, caCrtFile);
	crtPathC = jstring2Cstring(env, crtPath);

	if(load_ca(caKeyFileC, &caKey, caCrtFileC, &caCrt)){
		goto loadcaerr;
	}
	if(openssl_ca_create_crt(caKey, caCrt, req, &crt, term, evp_md)){
		goto caerr;
	}
	if(file_write_cert(crt, crtPathC)){
		goto caerr;
	}



	X509_free(crt);
	EVP_PKEY_free(caKey);
	X509_free(caCrt);
	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
	free(caKeyFileC);
	free(caCrtFileC);
	free(crtPathC);
	free(csrPathC);
	free(keyPathC);
	free(cC);
	free(stC);
	free(lC);
	free(oC);
	free(ouC);
	free(cnC);
	cleanup_crypto();
	return 0;
	generr:
		EVP_PKEY_free(pkey);
		free(keyPathC);
		cleanup_crypto();
		return 1;
	reqerr:
		EVP_PKEY_free(pkey);
		X509_REQ_free(req);
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		cleanup_crypto();
		return 2;
	loadcaerr:
		EVP_PKEY_free(caKey);
		X509_free(caCrt);
		X509_REQ_free(req);
		EVP_PKEY_free(pkey);
		free(caKeyFileC);
		free(caCrtFileC);
		free(crtPathC);
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		cleanup_crypto();
		return 3;
	caerr:
		X509_free(crt);
		EVP_PKEY_free(caKey);
		X509_free(caCrt);
		X509_REQ_free(req);
		EVP_PKEY_free(pkey);
		free(caKeyFileC);
		free(caCrtFileC);
		free(crtPathC);
		free(csrPathC);
		free(keyPathC);
		free(cC);
		free(stC);
		free(lC);
		free(oC);
		free(ouC);
		free(cnC);
		cleanup_crypto();
		return 4;
}
