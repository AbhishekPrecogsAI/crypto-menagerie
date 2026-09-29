/* legacy_crypto.c — direct OpenSSL calls into deprecated primitives.
 * Expected CBOM: MD5 (via EVP), DES-ECB (no IV, deterministic), and a
 * 1024-bit RSA key generation. Native/firmware-style crypto usage. */
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <string.h>

/* MD5 digest — broken, kept only for a legacy checksum. */
void legacy_md5(const unsigned char *in, size_t len, unsigned char out[16]) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, in, len);
    MD5_Final(out, &ctx);
}

/* DES-ECB — 56-bit key, ECB mode (no diffusion). */
void legacy_des_ecb(const_DES_cblock *key, DES_cblock *in, DES_cblock *out) {
    DES_key_schedule ks;
    DES_set_key_unchecked(key, &ks);
    DES_ecb_encrypt(in, out, &ks, DES_ENCRYPT);
}

/* Generate a 1024-bit RSA key — below the modern floor. */
RSA *weak_rsa_keygen(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, e, NULL); /* 1024 bits — deprecated */
    BN_free(e);
    return rsa;
}
