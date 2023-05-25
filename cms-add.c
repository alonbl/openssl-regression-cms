#include <stdio.h>
#include <string.h>

#include <openssl/cms.h>
#include <openssl/err.h>

void openssl_error(const char * const msg) {
	fprintf(stderr, "openssl error %s\n", msg);
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	ERR_print_errors(bio);
	BIO_free(bio);
}

int main(int argc, char *argv[]) {
	int arg = 1;
	char *cms_in_name = argv[arg++];
	char *cms_out_name = argv[arg++];
	char *evp_key_name = argv[arg++];
	char *x509_name = argv[arg++];
	char *x509_to_name = argv[arg++];
	char *skip = argv[arg++];

	BIO *bio_cms_in = NULL;
	BIO *bio_cms_out = NULL;
	BIO *bio_evp_pkey = NULL;
	BIO *bio_x509 = NULL;
	BIO *bio_x509_to = NULL;
	EVP_PKEY *evp_pkey = NULL;
	X509 *x509 = NULL;
	X509 *x509_to = NULL;
	CMS_ContentInfo *cms = NULL;
	CMS_RecipientInfo *ri = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;
	int ret = 1;

	if ((bio_cms_in = BIO_new_file(cms_in_name, "rb")) == NULL) {
		openssl_error("BIO_new_file/bio_cms_in");
		goto cleanup;
	}

	if ((bio_cms_out = BIO_new_file(cms_out_name, "wb")) == NULL) {
		openssl_error("BIO_new_file/bio_cms_out");
		goto cleanup;
	}

	if ((bio_evp_pkey = BIO_new_file(evp_key_name, "rb")) == NULL) {
		openssl_error("BIO_new_file/bio_evp_pkey");
		goto cleanup;
	}

	if ((bio_x509 = BIO_new_file(x509_name, "rb")) == NULL) {
		openssl_error("BIO_new_file/bio_x509");
		goto cleanup;
	}

	if ((bio_x509_to = BIO_new_file(x509_to_name, "rb")) == NULL) {
		openssl_error("BIO_new_file/bio_x509_to");
		goto cleanup;
	}

	if ((evp_pkey = d2i_PrivateKey_bio(bio_evp_pkey, NULL)) == NULL) {
		openssl_error("d2i_PrivateKey_bio/bio_evp_pkey");
		goto cleanup;
	}

	if ((x509 = d2i_X509_bio(bio_x509, NULL)) == NULL) {
		openssl_error("d2i_X509_bio/bio_x509");
		goto cleanup;
	}

	if ((x509_to = d2i_X509_bio(bio_x509_to, NULL)) == NULL) {
		openssl_error("d2i_X509_bio/bio_x509_to");
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(bio_cms_in, NULL)) == NULL) {
		openssl_error("d2i_CMS_bio");
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, evp_pkey, x509)) {
		openssl_error("CMS_decrypt_set1_pkey");
		goto cleanup;
	}

	if ((ri = CMS_add1_recipient_cert(cms, x509_to, flags)) == NULL) {
		openssl_error("CMS_add1_recipient_cert");
		goto cleanup;
	}

	if (!CMS_RecipientInfo_encrypt(cms, ri)) {
		openssl_error("CMS_RecipientInfo_encrypt");
		goto cleanup;
	}

	if (strcmp(skip, "1")) {
		if (!CMS_final(cms, NULL, NULL, flags)) {
			openssl_error("CMS_final");
			goto cleanup;
		}
	}

	if (i2d_CMS_bio(bio_cms_out, cms)  <= 0) {
		openssl_error("i2d_CMS_bio/i2d_CMS_bio");
		goto cleanup;
	}

	ret = 0;

cleanup:
	CMS_ContentInfo_free(cms);
	X509_free(x509);
	X509_free(x509_to);
	EVP_PKEY_free(evp_pkey);
	BIO_free(bio_evp_pkey);
	BIO_free(bio_x509);
	BIO_free(bio_x509_to);
	BIO_free(bio_cms_in);
	BIO_free(bio_cms_out);

	return ret;
}
