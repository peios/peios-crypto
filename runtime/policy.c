/* The policy runtime's checks, which the generated hooks call. Compiled
   against AWS-LC's prefixed headers, so that it calls AWS-LC directly
   rather than through libpcrypto's own hooks.

   Until the runtime reads the machine's policy, it applies Peios's
   defaults: nothing above the floor is refused, grades below C are warned
   about, and FIPS is off. Warnings aren't reported yet. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/bn.h>
#include <openssl/cipher.h>
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/experimental/kem_deterministic_api.h>
#include <openssl/hpke.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "peios_policy.h"
#include "policy_ids.h"

static const struct peios_policy default_policy = {
    .reject_below = PEIOS_GRADE_U,
    .warn_below = PEIOS_GRADE_C,
    .reject_non_fips = 0,
    .warn_non_fips = 0,
};

/* Whether the call using `algorithm`, or an ungraded algorithm if it's
   NULL, may go ahead. */
static int decide(const struct peios_algorithm *algorithm) {
    if (algorithm == NULL) {
        ERR_put_error(ERR_LIB_USER, 0, PEIOS_R_UNGRADED_ALGORITHM, __FILE__, __LINE__);
        return 0;
    }
    if (peios_policy_decision(algorithm, &default_policy) == PEIOS_REJECT) {
        ERR_put_error(ERR_LIB_USER, 0, PEIOS_R_REFUSED_BY_POLICY, __FILE__, __LINE__);
        return 0;
    }
    return 1;
}

/* A NULL method chooses no algorithm: the call continues with the one its
   context already has, which was checked when it was chosen, or fails in
   AWS-LC. */
int peios_policy_digest(const EVP_MD *md, enum peios_operation op) {
    if (md == NULL) {
        return 1;
    }
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->kind == PEIOS_KIND_DIGEST && a->op == op && a->md() == md) {
            return decide(a);
        }
    }
    return decide(NULL);
}

int peios_policy_cipher(const EVP_CIPHER *cipher, enum peios_operation op) {
    if (cipher == NULL) {
        return 1;
    }
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->kind == PEIOS_KIND_CIPHER && a->op == op && a->cipher() == cipher) {
            return decide(a);
        }
    }
    return decide(NULL);
}

int peios_policy_cipher_init(const EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, int enc) {
    if (ctx == NULL) {
        return 1;
    }
    if (enc == -1) {
        if (cipher == NULL) {
            return 1;
        }
        enc = EVP_CIPHER_CTX_encrypting(ctx);
    }
    if (cipher == NULL) {
        cipher = EVP_CIPHER_CTX_cipher(ctx);
    }
    return peios_policy_cipher(cipher, enc ? PEIOS_OP_ENCRYPT : PEIOS_OP_DECRYPT);
}

int peios_policy_aead(const EVP_AEAD *aead, enum peios_operation op) {
    if (aead == NULL) {
        return 1;
    }
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->kind == PEIOS_KIND_AEAD && a->op == op && a->aead() == aead) {
            return decide(a);
        }
    }
    return decide(NULL);
}

int peios_policy_algorithm(const struct peios_algorithm *algorithm) {
    return decide(algorithm);
}

int peios_policy_pkcs12_pbe(int nid) {
    switch (nid) {
        case -1:
            return 1;
        case NID_pbe_WithSHA1And40BitRC2_CBC:
            return decide(PEIOS_ENTRY_pkcs12_pbe_sha1_rc2_40_encrypt);
        case NID_pbe_WithSHA1And128BitRC4:
            return decide(PEIOS_ENTRY_pkcs12_pbe_sha1_rc4_128_encrypt);
        case NID_pbe_WithSHA1And3_Key_TripleDES_CBC:
            return decide(PEIOS_ENTRY_pkcs12_pbe_sha1_3des_encrypt);
        default:
            return decide(NULL);
    }
}

void peios_policy_abort(const char *function) {
    fprintf(stderr,
            "libpcrypto: Peios crypto policy refused %s, which can't report failure; "
            "ending the process\n",
            function);
    abort();
}

/* The entry grading `op` on a key of `kind` with `bits` bits, or NULL. */
static const struct peios_algorithm *by_bits(enum peios_kind kind, int bits,
                                             enum peios_operation op) {
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->kind == kind && a->op == op && bits >= a->min_bits && bits <= a->max_bits) {
            return a;
        }
    }
    return NULL;
}

/* The entry grading `op` on a key of `kind` whose curve or parameter set
   is `nid`, or NULL. NID_undef, a custom curve's, is never graded. */
static const struct peios_algorithm *by_nid(enum peios_kind kind, int nid,
                                            enum peios_operation op) {
    for (unsigned i = 0; nid != NID_undef && i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->kind == kind && a->op == op && a->nid == nid) {
            return a;
        }
    }
    return NULL;
}

/* The entry grading `op` on the algorithm algorithms.toml names `name`,
   or NULL. */
static const struct peios_algorithm *by_name(const char *name, enum peios_operation op) {
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->op == op && strcmp(a->name, name) == 0) {
            return a;
        }
    }
    return NULL;
}

int peios_policy_rsa_keygen(int bits) {
    return decide(by_bits(PEIOS_KIND_RSA, bits, PEIOS_OP_KEYGEN));
}

/* A key without its modulus, or parameters without their prime, chooses
   nothing to grade: AWS-LC reports the missing value itself. Reading its
   size here would crash where AWS-LC fails cleanly. */
int peios_policy_rsa(const RSA *rsa, enum peios_operation op) {
    if (rsa == NULL || RSA_get0_n(rsa) == NULL || BN_is_zero(RSA_get0_n(rsa))) {
        return 1;
    }
    return decide(by_bits(PEIOS_KIND_RSA, (int)RSA_bits(rsa), op));
}

int peios_policy_rsa_padding(int padding, enum peios_operation op) {
    switch (padding) {
        case RSA_NO_PADDING:
            return decide(by_name("rsa-no-padding", op));
        case RSA_X931_PADDING:
            /* AWS-LC supports X9.31 only for signatures, and reports it
               unsupported for anything else itself. */
            if (op == PEIOS_OP_SIGN || op == PEIOS_OP_VERIFY) {
                return decide(by_name("rsa-x931", op));
            }
            return 1;
        case RSA_PKCS1_PADDING:
            if (op == PEIOS_OP_ENCRYPT || op == PEIOS_OP_DECRYPT) {
                return decide(by_name("rsa-pkcs1v15-encryption", op));
            }
            return 1;
        default:
            return 1;
    }
}

/* A digest named by its NID, for a signature: NID_md5_sha1 is TLS 1.0's
   and 1.1's, which EVP_get_digestbynid doesn't know. */
static int signature_digest(int hash_nid) {
    if (hash_nid == NID_undef) {
        return 1;
    }
    const EVP_MD *md = hash_nid == NID_md5_sha1 ? EVP_md5_sha1() : EVP_get_digestbynid(hash_nid);
    return md != NULL ? peios_policy_digest(md, PEIOS_OP_DIGEST) : decide(NULL);
}

int peios_policy_rsa_nid(const RSA *rsa, int hash_nid, enum peios_operation op) {
    return peios_policy_rsa(rsa, op) && signature_digest(hash_nid);
}

int peios_policy_dh_bits(int bits, enum peios_operation op) {
    return decide(by_bits(PEIOS_KIND_DH, bits, op));
}

int peios_policy_dh(const DH *dh, enum peios_operation op) {
    if (dh == NULL || DH_get0_p(dh) == NULL) {
        return 1;
    }
    return peios_policy_dh_bits((int)DH_bits(dh), op);
}

/* A curve given by explicit parameters has no NID, but may be a named
   curve all the same: it's graded as the built-in curve it equals, and is
   ungraded, so refused, only if it equals none. */
static int curve_nid(const EC_GROUP *group) {
    int nid = EC_GROUP_get_curve_name(group);
    if (nid != NID_undef) {
        return nid;
    }
    const EC_GROUP *(*const named[])(void) = {
        EC_group_p224, EC_group_p256, EC_group_p384, EC_group_p521,
        EC_group_secp256k1, EC_group_brainpoolP224r1, EC_group_brainpoolP256r1,
        EC_group_brainpoolP320r1, EC_group_brainpoolP384r1, EC_group_brainpoolP512r1,
    };
    for (size_t i = 0; i < sizeof(named) / sizeof(named[0]); i++) {
        if (EC_GROUP_cmp(group, named[i](), NULL) == 0) {
            return EC_GROUP_get_curve_name(named[i]());
        }
    }
    return NID_undef;
}

int peios_policy_ec_group(const EC_GROUP *group, enum peios_operation op) {
    if (group == NULL) {
        return 1;
    }
    return decide(by_nid(PEIOS_KIND_EC, curve_nid(group), op));
}

int peios_policy_ec_key(const EC_KEY *key, enum peios_operation op) {
    if (key == NULL) {
        return 1;
    }
    return peios_policy_ec_group(EC_KEY_get0_group(key), op);
}

int peios_policy_pkey(const EVP_PKEY *pkey, enum peios_operation op) {
    if (pkey == NULL) {
        return 1;
    }
    switch (EVP_PKEY_id(pkey)) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS:
            return peios_policy_rsa(EVP_PKEY_get0_RSA(pkey), op);
        case EVP_PKEY_DH:
            return peios_policy_dh(EVP_PKEY_get0_DH(pkey), op);
        case EVP_PKEY_EC:
            return peios_policy_ec_key(EVP_PKEY_get0_EC_KEY(pkey), op);
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED25519PH:
            return decide(by_name("ed25519", op));
        case EVP_PKEY_X25519:
            return decide(by_name("x25519", op));
        case EVP_PKEY_DSA:
            return decide(by_name("dsa", op));
        case EVP_PKEY_PQDSA:
            return decide(by_nid(PEIOS_KIND_PQDSA, EVP_PKEY_pqdsa_get_type(pkey), op));
        case EVP_PKEY_KEM:
            return decide(by_nid(PEIOS_KIND_KEM, EVP_PKEY_kem_get_type(pkey), op));
        case EVP_PKEY_HMAC:
        case EVP_PKEY_HKDF:
            /* Their algorithm is their digest, checked where it's chosen. */
            return 1;
        case EVP_PKEY_NONE:
            /* An empty key, which AWS-LC reports. */
            return 1;
        default:
            return decide(NULL);
    }
}

int peios_policy_pkey_md(const EVP_PKEY *pkey, const EVP_MD *md, enum peios_operation op) {
    if (pkey != NULL && EVP_PKEY_id(pkey) == EVP_PKEY_HMAC) {
        return peios_policy_digest(md, PEIOS_OP_HMAC);
    }
    return peios_policy_pkey(pkey, op) && peios_policy_digest(md, PEIOS_OP_DIGEST);
}

int peios_policy_pkey_ctx(EVP_PKEY_CTX *ctx, enum peios_operation op) {
    if (ctx == NULL) {
        return 1;
    }
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey == NULL) {
        /* A context with no key, HKDF's say: its parameters are checked as
           they're set. */
        return 1;
    }
    int id = EVP_PKEY_id(pkey);
    int rsa = id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS;
    const EVP_MD *md = NULL;
    if ((op == PEIOS_OP_SIGN || op == PEIOS_OP_VERIFY) &&
        (rsa || id == EVP_PKEY_EC || id == EVP_PKEY_DSA)) {
        EVP_PKEY_CTX_get_signature_md(ctx, &md);
    }
    if (!peios_policy_pkey_md(pkey, md, op)) {
        return 0;
    }
    int padding;
    if (rsa && EVP_PKEY_CTX_get_rsa_padding(ctx, &padding)) {
        return peios_policy_rsa_padding(padding, op);
    }
    return 1;
}

int peios_policy_signature(int sig_nid, const EVP_PKEY *pkey, enum peios_operation op) {
    int hash_nid, pkey_nid;
    if (!OBJ_find_sigid_algs(sig_nid, &hash_nid, &pkey_nid)) {
        return decide(NULL);
    }
    return peios_policy_pkey(pkey, op) && signature_digest(hash_nid);
}

int peios_policy_hpke(const EVP_HPKE_KEM *kem, const EVP_HPKE_KDF *kdf,
                      const EVP_HPKE_AEAD *aead, int sender) {
    if (kem == NULL || kdf == NULL || aead == NULL) {
        /* A zeroed key or missing algorithm, which AWS-LC reports. */
        return 1;
    }
    enum peios_operation kem_op = sender ? PEIOS_OP_ENCAPSULATE : PEIOS_OP_DECAPSULATE;
    const struct peios_algorithm *kem_entry = NULL;
    if (kem == EVP_hpke_x25519_hkdf_sha256()) {
        kem_entry = by_name("x25519", PEIOS_OP_DERIVE);
    } else if (kem == EVP_hpke_mlkem512()) {
        kem_entry = by_nid(PEIOS_KIND_KEM, NID_MLKEM512, kem_op);
    } else if (kem == EVP_hpke_mlkem768()) {
        kem_entry = by_nid(PEIOS_KIND_KEM, NID_MLKEM768, kem_op);
    } else if (kem == EVP_hpke_mlkem1024()) {
        kem_entry = by_nid(PEIOS_KIND_KEM, NID_MLKEM1024, kem_op);
    }
    if (!decide(kem_entry)) {
        return 0;
    }
    const EVP_MD *kdf_md = kdf == EVP_hpke_hkdf_sha256() ? EVP_sha256()
                           : kdf == EVP_hpke_hkdf_sha384() ? EVP_sha384()
                                                           : NULL;
    if (kdf_md == NULL) {
        return decide(NULL);
    }
    if (!decide(PEIOS_ENTRY_hkdf_kdf) || !peios_policy_digest(kdf_md, PEIOS_OP_HMAC)) {
        return 0;
    }
    enum peios_operation aead_op = sender ? PEIOS_OP_ENCRYPT : PEIOS_OP_DECRYPT;
    if (aead == EVP_hpke_aes_128_gcm()) {
        return peios_policy_aead(EVP_aead_aes_128_gcm(), aead_op);
    }
    if (aead == EVP_hpke_aes_256_gcm()) {
        return peios_policy_aead(EVP_aead_aes_256_gcm(), aead_op);
    }
    if (aead == EVP_hpke_chacha20_poly1305()) {
        return peios_policy_aead(EVP_aead_chacha20_poly1305(), aead_op);
    }
    return decide(NULL);
}

int peios_policy_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **out_pkey) {
    if (!EVP_PKEY_keygen(ctx, out_pkey)) {
        return 0;
    }
    if (peios_policy_pkey(*out_pkey, PEIOS_OP_KEYGEN)) {
        return 1;
    }
    EVP_PKEY_free(*out_pkey);
    *out_pkey = NULL;
    return 0;
}

int peios_policy_keygen_deterministic(EVP_PKEY_CTX *ctx, EVP_PKEY **out_pkey,
                                      const uint8_t *seed, size_t *seed_len) {
    if (!EVP_PKEY_keygen_deterministic(ctx, out_pkey, seed, seed_len)) {
        return 0;
    }
    if (out_pkey == NULL || peios_policy_pkey(*out_pkey, PEIOS_OP_KEYGEN)) {
        return 1;
    }
    EVP_PKEY_free(*out_pkey);
    *out_pkey = NULL;
    return 0;
}

int peios_policy_hpke_kem(const EVP_HPKE_KEM *kem, enum peios_operation op) {
    if (kem == NULL) {
        return 1;
    }
    if (kem == EVP_hpke_x25519_hkdf_sha256()) {
        return decide(by_name("x25519", op));
    }
    int nid = kem == EVP_hpke_mlkem512()    ? NID_MLKEM512
              : kem == EVP_hpke_mlkem768()  ? NID_MLKEM768
              : kem == EVP_hpke_mlkem1024() ? NID_MLKEM1024
                                            : NID_undef;
    return decide(by_nid(PEIOS_KIND_KEM, nid, op));
}

int peios_policy_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **out_pkey) {
    if (!EVP_PKEY_paramgen(ctx, out_pkey)) {
        return 0;
    }
    if (peios_policy_pkey(*out_pkey, PEIOS_OP_KEYGEN)) {
        return 1;
    }
    EVP_PKEY_free(*out_pkey);
    *out_pkey = NULL;
    return 0;
}

int peios_policy_verify_cert(X509_STORE_CTX *ctx) {
    int ok = X509_verify_cert(ctx);
    if (ok <= 0) {
        return ok;
    }
    /* Each certificate's signature, checked with its issuer's key. The last
       is the trust anchor, whose own signature AWS-LC doesn't check. */
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    size_t n = sk_X509_num(chain);
    for (size_t i = 0; i + 1 < n; i++) {
        X509 *cert = sk_X509_value(chain, i);
        EVP_PKEY *issuer_key = X509_get0_pubkey(sk_X509_value(chain, i + 1));
        if (!peios_policy_signature(X509_get_signature_nid(cert), issuer_key,
                                    PEIOS_OP_VERIFY)) {
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
            return 0;
        }
    }
    return 1;
}
