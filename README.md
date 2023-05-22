# [REGRESSION] CMS_final fails (openssl>=3.0.8, openssl>=3.1.0)

## Outline

Previous implementation required `CMS_final` in order to encrypt and finalize
the CMS before serialization.

The `CMS_final` fails with:

```
802BF10400000000:error:100C0102:BIO routines:bio_read_intern:passed a null parameter:crypto/bio/bio_lib.c:274:
802BF10400000000:error:1C80006B:Provider routines:ossl_cipher_generic_block_final:wrong final block length:providers/implementations/ciphers/ciphercommon.c:429:
```

Interesting enough removing the `CMS_final` produces a valid CMS, however it
does leaks resources.

## Reproduction

* data.pt: plain text data
* data.ct: detached ciphered text data, encrypted to `test1.crt`
* test1.crt
* test1.key
* test3.crt
* test3.key

The project adds `test3` as recipient and then decrypt the cipher text using
`test1` and `test3` keys.

Please checkout the `check` target which shows the regression and the
`check-workaround` target which proves regression.

## References

* Reproduction: https://github.com/alonbl/openssl-regression-cms
  * "Fix SMIME_crlf_copy() to properly report an error"
* Reported: https://github.com/openssl/openssl/issues/21026
* Root cause: https://github.com/openssl/openssl/pull/19919
