#include <stdio.h>

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
	char *cms_name = argv[arg++];
	char *evp_key_name = argv[arg++];
	char *x509_name = argv[arg++];
	char *ct_name = argv[arg++];
	char *pt_name = argv[arg++];

	BIO *bio_data_pt = NULL;
	BIO *bio_data_ct = NULL;
	BIO *bio_cms_in = NULL;
	BIO *bio_evp_pkey = NULL;
	BIO *bio_x509 = NULL;
	EVP_PKEY *evp_pkey = NULL;
	X509 *x509 = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED;
	int ret = 1;

	if ((bio_data_ct = BIO_new_file(ct_name, "rb")) == NULL) {
		openssl_error("BIO_new_file/bio_data_ct");
		goto cleanup;
	}

	if ((bio_data_pt = BIO_new_file(pt_name, "wb")) == NULL) {
		openssl_error("BIO_new_file/bio_data_pt");
		goto cleanup;
	}

	if ((bio_cms_in = BIO_new_file(cms_name, "rb")) == NULL) {
		openssl_error("BIO_new_file/bio_cms_in");
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

	if ((evp_pkey = d2i_PrivateKey_bio(bio_evp_pkey, NULL)) == NULL) {
		openssl_error("d2i_PrivateKey_bio/bio_evp_pkey");
		goto cleanup;
	}

	if ((x509 = d2i_X509_bio(bio_x509, NULL)) == NULL) {
		openssl_error("d2i_X509_bio/bio_x509");
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

	if (!CMS_decrypt(cms, NULL, NULL, bio_data_ct, bio_data_pt, flags)) {
		openssl_error("CMS_decrypt");
		goto cleanup;
	}

	ret = 0;

cleanup:
	CMS_ContentInfo_free(cms);
	X509_free(x509);
	EVP_PKEY_free(evp_pkey);
	BIO_free(bio_evp_pkey);
	BIO_free(bio_x509);
	BIO_free(bio_cms_in);
	BIO_free(bio_data_ct);
	BIO_free(bio_data_pt);

	return ret;
}
