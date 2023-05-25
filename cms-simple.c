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
	char *cms_in_name = argv[arg++];
	char *cms_out_name = argv[arg++];

	BIO *bio_cms_in = NULL;
	BIO *bio_cms_out = NULL;
	CMS_ContentInfo *cms = NULL;
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

	if ((cms = d2i_CMS_bio(bio_cms_in, NULL)) == NULL) {
		openssl_error("d2i_CMS_bio");
		goto cleanup;
	}

	if (i2d_CMS_bio_stream(bio_cms_out, cms, NULL, flags)  <= 0) {
		openssl_error("i2d_CMS_bio/i2d_CMS_bio");
		goto cleanup;
	}

	ret = 0;

cleanup:
	CMS_ContentInfo_free(cms);
	BIO_free(bio_cms_in);
	BIO_free(bio_cms_out);

	return ret;
}
