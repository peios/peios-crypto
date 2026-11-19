// libpcrypto's policy hooks, as a program reaches them. Under Peios's
// default policy, only the floor is refused: the null cipher and RSA keys
// under 1024 bits. An algorithm the policy doesn't grade is refused too,
// and every digest and cipher AWS-LC can look up is graded.

#include <stdio.h>

#include <string.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/cipher.h>
#include <openssl/cmac.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/poly1305.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/siphash.h>

// libpcrypto's reasons, in ERR_LIB_USER.
#define REFUSED_BY_POLICY 1000
#define UNGRADED_ALGORITHM 1001

static int failures = 0;

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "policy_hooks: %s\n", what);
        failures++;
    }
}

// Whether the error queue's first error is libpcrypto's `reason`; clears
// the queue.
static int refused_with(int reason) {
    uint32_t error = ERR_get_error();
    ERR_clear_error();
    return ERR_GET_LIB(error) == ERR_LIB_USER && ERR_GET_REASON(error) == reason;
}

static int digest_allowed(const EVP_MD *md) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestInit_ex(ctx, md, NULL);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int encrypt_allowed(const EVP_CIPHER *cipher, int encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = encrypt ? EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)
                     : EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int rsa_allowed(int bits) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    int ok = RSA_generate_key_ex(rsa, bits, e, NULL);
    BN_free(e);
    RSA_free(rsa);
    return ok;
}

int main(void) {
    check(digest_allowed(EVP_sha256()), "SHA-256 was refused");
    check(digest_allowed(EVP_md5()), "MD5, grade U, was refused under the default policy");

    static const uint8_t key[32] = {0};
    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    check(HMAC_Init_ex(&hmac, key, sizeof(key), EVP_sha256(), NULL), "HMAC-SHA-256 was refused");
    check(!HMAC_Init_ex(&hmac, key, sizeof(key), EVP_shake128(), NULL) &&
              refused_with(UNGRADED_ALGORITHM),
          "HMAC over SHAKE128, which isn't graded, wasn't refused as ungraded");
    HMAC_CTX_cleanup(&hmac);

    check(encrypt_allowed(EVP_aes_128_gcm(), 1), "AES-128-GCM encryption was refused");
    check(encrypt_allowed(EVP_des_ede3_cbc(), 0), "Triple DES decryption was refused");
    check(!encrypt_allowed(EVP_enc_null(), 1) && refused_with(REFUSED_BY_POLICY),
          "the null cipher wasn't refused for encryption");
    check(!encrypt_allowed(EVP_enc_null(), 0) && refused_with(REFUSED_BY_POLICY),
          "the null cipher wasn't refused for decryption");

    check(!rsa_allowed(512) && refused_with(REFUSED_BY_POLICY),
          "a 512-bit RSA key wasn't refused");
    check(rsa_allowed(2048), "a 2048-bit RSA key was refused");

    // The hooked one-shot and low-level digests and MACs still compute.
    static const uint8_t abc_sha256[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t out[64];
    check(SHA256((const uint8_t *)"abc", 3, out) == out && memcmp(out, abc_sha256, 32) == 0,
          "SHA256() gave the wrong digest");
    unsigned out_len = 0;
    check(EVP_Digest("abc", 3, out, &out_len, EVP_sha256(), NULL) && out_len == 32 &&
              memcmp(out, abc_sha256, 32) == 0,
          "EVP_Digest gave the wrong digest");
    MD5_CTX md5;
    check(MD5_Init(&md5) && MD5_Update(&md5, "abc", 3) && MD5_Final(out, &md5),
          "MD5_Init, MD5_Update and MD5_Final failed");
    check(HMAC(EVP_sha256(), key, sizeof(key), (const uint8_t *)"abc", 3, out, &out_len) != NULL,
          "HMAC() failed");

    CMAC_CTX *cmac = CMAC_CTX_new();
    check(CMAC_Init(cmac, key, 16, EVP_aes_128_cbc(), NULL), "AES-128 CMAC was refused");
    check(!CMAC_Init(cmac, key, 16, EVP_bf_cbc(), NULL) && refused_with(UNGRADED_ALGORITHM),
          "CMAC over Blowfish, which isn't graded, wasn't refused as ungraded");
    CMAC_CTX_free(cmac);
    check(AES_CMAC(out, key, 16, (const uint8_t *)"abc", 3), "AES_CMAC was refused");

    poly1305_state poly;
    CRYPTO_poly1305_init(&poly, key);
    CRYPTO_poly1305_update(&poly, (const uint8_t *)"abc", 3);
    CRYPTO_poly1305_finish(&poly, out);
    static const uint64_t siphash_key[2] = {1, 2};
    (void)SIPHASH_24(siphash_key, (const uint8_t *)"abc", 3);

    // A cipher context turned to the other direction is checked again, and
    // allowed here.
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    check(EVP_DecryptInit_ex(cctx, EVP_aes_128_cbc(), NULL, key, key) &&
              EVP_EncryptInit_ex(cctx, NULL, NULL, key, key) &&
              EVP_CipherInit_ex(cctx, NULL, NULL, NULL, NULL, -1),
          "re-initialising an AES-128-CBC context was refused");
    EVP_CIPHER_CTX_free(cctx);

    // AEADs: the TLS NULL-cipher AEAD is on the floor.
    EVP_AEAD_CTX aead;
    check(EVP_AEAD_CTX_init(&aead, EVP_aead_aes_128_gcm(), key, 16, 16, NULL),
          "AES-128-GCM was refused");
    EVP_AEAD_CTX_cleanup(&aead);
    check(EVP_AEAD_CTX_init_with_direction(&aead, EVP_aead_chacha20_poly1305(), key, 32, 16,
                                           evp_aead_open),
          "ChaCha20-Poly1305 opening was refused");
    EVP_AEAD_CTX_cleanup(&aead);
    check(EVP_AEAD_CTX_new(EVP_aead_null_sha1_tls(), key, 20, 20) == NULL &&
              refused_with(REFUSED_BY_POLICY),
          "the NULL-cipher TLS AEAD wasn't refused by EVP_AEAD_CTX_new");
    check(!EVP_AEAD_CTX_init_with_direction(&aead, EVP_aead_null_sha1_tls(), key, 20, 20,
                                            evp_aead_seal) &&
              refused_with(REFUSED_BY_POLICY),
          "the NULL-cipher TLS AEAD wasn't refused for sealing");

    // The low-level keying functions still key.
    AES_KEY aes;
    check(AES_set_encrypt_key(key, 128, &aes) == 0, "AES_set_encrypt_key failed");
    check(AES_set_decrypt_key(key, 256, &aes) == 0, "AES_set_decrypt_key failed");
    RC4_KEY rc4;
    RC4_set_key(&rc4, 16, key);

    // Every digest and cipher AWS-LC looks up by NID is graded: none is
    // refused as ungraded.
    for (int nid = 1; nid <= 1000; nid++) {
        const EVP_MD *md = EVP_get_digestbynid(nid);
        if (md != NULL && !digest_allowed(md)) {
            check(!refused_with(UNGRADED_ALGORITHM), "a digest AWS-LC offers isn't graded");
        }
        const EVP_CIPHER *cipher = EVP_get_cipherbynid(nid);
        if (cipher != NULL && !encrypt_allowed(cipher, 1)) {
            check(!refused_with(UNGRADED_ALGORITHM), "a cipher AWS-LC offers isn't graded");
        }
    }

    if (failures == 0) {
        puts("policy_hooks: ok");
    }
    return failures != 0;
}
