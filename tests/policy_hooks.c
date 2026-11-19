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
#include <openssl/curve25519.h>
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/pkcs8.h>
#include <openssl/x509.h>
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

// A P-256 key and a self-signed certificate for it, for PKCS #12.
static X509 *self_signed(EVP_PKEY **key_out) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(key, ec);
    X509 *cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                               (const uint8_t *)"policy_hooks", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, EVP_sha256());
    *key_out = key;
    return cert;
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

    // Key derivation.
    check(PKCS5_PBKDF2_HMAC("pw", 2, key, 16, 1000, EVP_sha256(), 32, out),
          "PBKDF2-HMAC-SHA-256 was refused");
    check(HKDF(out, 32, EVP_sha256(), key, 32, NULL, 0, NULL, 0), "HKDF-SHA-256 was refused");
    check(EVP_PBE_scrypt("pw", 2, key, 16, 1024, 8, 1, 0, out, 32), "scrypt was refused");
    check(CRYPTO_tls1_prf(EVP_md5_sha1(), out, 32, key, 32, "label", 5, key, 16, NULL, 0),
          "TLS 1.0's PRF was refused under the default policy");
    check(CRYPTO_tls1_prf(EVP_sha256(), out, 32, key, 32, "label", 5, key, 16, NULL, 0),
          "TLS 1.2's PRF was refused");

    // Encrypted keys and PKCS #12: PKCS #12's RC2-40 is on the floor, and
    // it's AWS-LC's default for PKCS12_create's certificates.
    EVP_PKEY *pkey = NULL;
    X509 *cert = self_signed(&pkey);
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
    check(PKCS8_encrypt(NID_pbe_WithSHA1And40BitRC2_CBC, NULL, "pw", 2, NULL, 0, 1000, p8) ==
                  NULL &&
              refused_with(REFUSED_BY_POLICY),
          "PKCS #8 encryption with RC2-40 wasn't refused");
    X509_SIG *sig = PKCS8_encrypt(-1, EVP_aes_256_cbc(), "pw", 2, NULL, 0, 1000, p8);
    check(sig != NULL, "PKCS #8 encryption with PBES2 and AES-256 was refused");
    X509_SIG_free(sig);
    PKCS8_PRIV_KEY_INFO_free(p8);
    check(PKCS12_create("pw", "name", pkey, cert, NULL, 0, 0, 0, 0, 0) == NULL &&
              refused_with(REFUSED_BY_POLICY),
          "PKCS12_create's default RC2-40 certificate encryption wasn't refused");
    PKCS12 *p12 = PKCS12_create("pw", "name", pkey, cert, NULL, 0, -1, 0, 0, 0);
    check(p12 != NULL, "PKCS12_create with unencrypted certificates was refused");
    PKCS12_free(p12);

    // Public keys. A generated key is checked once generated: AWS-LC makes
    // a 512-bit RSA key, and the hook refuses and frees it.
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *generated = NULL;
    check(EVP_PKEY_keygen_init(kctx) && EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 512) &&
              !EVP_PKEY_keygen(kctx, &generated) && generated == NULL &&
              refused_with(REFUSED_BY_POLICY),
          "EVP_PKEY_keygen kept a 512-bit RSA key");
    check(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) && EVP_PKEY_keygen(kctx, &generated),
          "EVP_PKEY_keygen refused a 2048-bit RSA key");
    EVP_PKEY_free(generated);
    EVP_PKEY_CTX_free(kctx);

    // Signing with the certificate's P-256 key, and verifying the
    // self-signed certificate as a chain of one.
    EVP_MD_CTX *sign = EVP_MD_CTX_new();
    uint8_t signature[128];
    size_t sig_len = sizeof(signature);
    check(EVP_DigestSignInit(sign, NULL, EVP_sha256(), NULL, pkey) &&
              EVP_DigestSign(sign, signature, &sig_len, (const uint8_t *)"abc", 3),
          "ECDSA P-256 with SHA-256 was refused");
    EVP_MD_CTX_free(sign);
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, cert);
    X509_STORE_CTX *vctx = X509_STORE_CTX_new();
    check(X509_STORE_CTX_init(vctx, store, cert, NULL) && X509_verify_cert(vctx) == 1,
          "a self-signed P-256 certificate didn't verify");
    X509_STORE_CTX_free(vctx);
    X509_STORE_free(store);

    uint8_t ed_public[32], ed_private[64], x_public[32], x_private[32], shared[32];
    ED25519_keypair(ed_public, ed_private);
    check(ED25519_sign(signature, (const uint8_t *)"abc", 3, ed_private) &&
              ED25519_verify((const uint8_t *)"abc", 3, signature, ed_public),
          "Ed25519 was refused");
    X25519_keypair(x_public, x_private);
    check(X25519(shared, x_private, x_public), "X25519 was refused");

    DH *dh = DH_new();
    check(!DH_generate_parameters_ex(dh, 512, 2, NULL) && refused_with(REFUSED_BY_POLICY),
          "512-bit Diffie-Hellman parameters weren't refused");
    DH_free(dh);

    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    uint8_t digest[32] = {0}, nonce[32] = {1};
    check(ECDSA_sign_with_nonce_and_leak_private_key_for_testing(digest, 32, ec, nonce, 32) ==
                  NULL &&
              refused_with(REFUSED_BY_POLICY),
          "ECDSA with a fixed nonce wasn't refused");

    EVP_PKEY_CTX *mlkem = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
    EVP_PKEY *kem_key = NULL;
    check(EVP_PKEY_CTX_kem_set_params(mlkem, NID_MLKEM768) && EVP_PKEY_keygen_init(mlkem) &&
              EVP_PKEY_keygen(mlkem, &kem_key),
          "ML-KEM-768 key generation was refused");
    EVP_PKEY_free(kem_key);
    EVP_PKEY_CTX_free(mlkem);

    // PEM's legacy encryption is checked as its cipher and EVP_BytesToKey.
    BIO *pem = BIO_new(BIO_s_mem());
    check(PEM_write_bio_PrivateKey(pem, pkey, EVP_aes_256_cbc(), (uint8_t *)"pw", 2, NULL,
                                   NULL),
          "PEM encryption with AES-256-CBC was refused");
    check(!PEM_write_bio_PrivateKey(pem, pkey, EVP_enc_null(), (uint8_t *)"pw", 2, NULL, NULL) &&
              refused_with(REFUSED_BY_POLICY),
          "PEM \"encryption\" with the null cipher wasn't refused");
    BIO_free(pem);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    // What AWS-LC itself rejects fails with AWS-LC's error, not Peios's,
    // and doesn't crash: an operation with no context.
    ERR_clear_error();
    size_t ct_len = 0, ss_len = 0;
    check(!EVP_PKEY_encapsulate(NULL, NULL, &ct_len, NULL, &ss_len) &&
              ERR_GET_LIB(ERR_peek_error()) != ERR_LIB_USER,
          "EVP_PKEY_encapsulate with no context failed with Peios's error");
    ERR_clear_error();

    // Every built-in curve is graded.
    EC_builtin_curve curves[16];
    size_t n_curves = EC_get_builtin_curves(curves, 16);
    for (size_t i = 0; i < n_curves; i++) {
        EC_KEY *curve_key = EC_KEY_new_by_curve_name(curves[i].nid);
        if (!EC_KEY_generate_key(curve_key)) {
            check(!refused_with(UNGRADED_ALGORITHM), "a built-in curve isn't graded");
        }
        EC_KEY_free(curve_key);
    }

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
