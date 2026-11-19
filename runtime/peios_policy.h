/* Peios crypto policy runtime: the interface between the generated hooks
   and policy table, and the runtime that decides. libpcrypto exports its
   peios_policy_ functions only in the version PEIOS_POLICY_PRIVATE, for
   libpssl's TLS checks; everything else here stays local. */
#ifndef PEIOS_POLICY_H
#define PEIOS_POLICY_H

#include <stddef.h>

struct env_md_st;
struct evp_cipher_st;
struct evp_cipher_ctx_st;
struct evp_aead_st;
struct evp_pkey_st;
struct evp_pkey_ctx_st;
struct rsa_st;
struct dh_st;
struct ec_key_st;
struct ec_group_st;
struct x509_st;
struct x509_store_ctx_st;
struct evp_hpke_kem_st;
struct evp_hpke_kdf_st;
struct evp_hpke_aead_st;

/* What an algorithms.toml entry grades. */
enum peios_kind {
    PEIOS_KIND_DIGEST,
    PEIOS_KIND_CIPHER,
    PEIOS_KIND_AEAD,
    /* Keys graded by their size, from `min_bits` to `max_bits`. */
    PEIOS_KIND_RSA,
    PEIOS_KIND_DH,
    /* Keys graded by their curve or parameter set, which `nid` names. */
    PEIOS_KIND_EC,
    PEIOS_KIND_PQDSA,
    PEIOS_KIND_KEM,
    /* An algorithm a function fixes by its name, MD5's or Poly1305's, which
       a hook names by its entry. */
    PEIOS_KIND_FIXED,
};

enum peios_operation {
    PEIOS_OP_DIGEST,
    PEIOS_OP_HMAC,
    PEIOS_OP_CMAC,
    PEIOS_OP_MAC,
    PEIOS_OP_KDF,
    PEIOS_OP_DRBG,
    PEIOS_OP_ENCRYPT,
    PEIOS_OP_DECRYPT,
    PEIOS_OP_KEYGEN,
    PEIOS_OP_SIGN,
    PEIOS_OP_VERIFY,
    PEIOS_OP_DERIVE,
    PEIOS_OP_ENCAPSULATE,
    PEIOS_OP_DECAPSULATE,
    PEIOS_OP_NEGOTIATE,
};

/* Lowest first, so that grades compare as numbers. */
enum peios_grade {
    PEIOS_GRADE_U,
    PEIOS_GRADE_D,
    PEIOS_GRADE_C,
    PEIOS_GRADE_B,
    PEIOS_GRADE_A,
};

/* One graded (algorithm, operation), as `id` names it: `md5.hmac`, say.
   A digest or cipher is found by comparing the method a caller passes with
   what `md` or `cipher` returns, as AWS-LC's methods are static; an RSA
   size by the band from `min_bits` to `max_bits`. `floor` refuses it
   whatever the policy. */
struct peios_algorithm {
    const char *id;
    /* The algorithm `id` grades an operation of: `md5` for `md5.hmac`. */
    const char *name;
    enum peios_kind kind;
    const struct env_md_st *(*md)(void);
    const struct evp_cipher_st *(*cipher)(void);
    const struct evp_aead_st *(*aead)(void);
    int min_bits;
    int max_bits;
    int nid;
    enum peios_operation op;
    enum peios_grade grade;
    int fips;
    int floor;
};

/* Generated from algorithms.toml. */
extern const struct peios_algorithm peios_algorithms[];
extern const unsigned peios_algorithm_count;

/* A machine's policy: grades below `reject_below` are refused and below
   `warn_below` warned about; with `reject_non_fips` or `warn_non_fips`,
   so is anything FIPS doesn't approve. */
struct peios_policy {
    enum peios_grade reject_below;
    enum peios_grade warn_below;
    int reject_non_fips;
    int warn_non_fips;
};

enum peios_decision {
    PEIOS_ALLOW,
    PEIOS_WARN,
    PEIOS_REJECT,
};

/* What `policy` decides for `algorithm`. */
enum peios_decision peios_policy_decision(const struct peios_algorithm *algorithm,
                                          const struct peios_policy *policy);

/* The hooks' checks. Each returns nonzero if the call may go ahead, and
   otherwise puts an error on the caller's error queue, in ERR_LIB_USER
   with one of the reasons below. An algorithm algorithms.toml doesn't
   grade is refused. */
int peios_policy_digest(const struct env_md_st *md, enum peios_operation op);
int peios_policy_cipher(const struct evp_cipher_st *cipher, enum peios_operation op);
int peios_policy_aead(const struct evp_aead_st *aead, enum peios_operation op);
int peios_policy_rsa_keygen(int bits);

/* The check for (re)initialising a cipher context: `cipher`, or the
   context's own if it's NULL, in the direction `enc` sets, or the
   context's own if it's -1, as `EVP_CipherInit_ex` reads them. A context
   checked for one direction can't be turned to the other unchecked. */
int peios_policy_cipher_init(const struct evp_cipher_ctx_st *ctx,
                             const struct evp_cipher_st *cipher, int enc);

/* The check for a function whose name fixes its algorithm: a hook passes
   the entry, which the generator finds by its id. */
int peios_policy_algorithm(const struct peios_algorithm *algorithm);

/* The check for encrypting with a PKCS #12 password-based scheme, by its
   NID, as `PKCS12_create` and `PKCS8_encrypt` take it; -1 encrypts
   nothing, and is allowed. */
int peios_policy_pkcs12_pbe(int nid);

/* Public keys. A key is graded by its family and its size, curve or
   parameter set; a signature also by its digest's `digest` grade, and an
   RSA operation by its padding. A key AWS-LC can hold but algorithms.toml
   doesn't grade, on a custom curve say, is refused. */
int peios_policy_pkey(const struct evp_pkey_st *pkey, enum peios_operation op);
int peios_policy_pkey_md(const struct evp_pkey_st *pkey, const struct env_md_st *md,
                         enum peios_operation op);
int peios_policy_pkey_ctx(struct evp_pkey_ctx_st *ctx, enum peios_operation op);
int peios_policy_rsa(const struct rsa_st *rsa, enum peios_operation op);
int peios_policy_rsa_padding(int padding, enum peios_operation op);
int peios_policy_rsa_nid(const struct rsa_st *rsa, int hash_nid, enum peios_operation op);
int peios_policy_dh(const struct dh_st *dh, enum peios_operation op);
int peios_policy_dh_bits(int bits, enum peios_operation op);
int peios_policy_ec_key(const struct ec_key_st *key, enum peios_operation op);
int peios_policy_ec_group(const struct ec_group_st *group, enum peios_operation op);

/* A signature whose algorithm `sig_nid` names, sha256WithRSAEncryption
   say, made or checked with `pkey`. */
int peios_policy_signature(int sig_nid, const struct evp_pkey_st *pkey,
                           enum peios_operation op);

/* The same, for a signature an AlgorithmIdentifier names. */
struct X509_algor_st;
int peios_policy_algor(const struct X509_algor_st *algor, const struct evp_pkey_st *pkey,
                       enum peios_operation op);

/* Encrypting a content key to a recipient's public key, as PKCS #7 does:
   with RSA, PKCS #1 v1.5 key transport. For one key, or every key in a
   stack of certificates. */
struct stack_st_X509;
int peios_policy_key_transport(const struct evp_pkey_st *pkey);
int peios_policy_key_transport_certs(const struct stack_st_X509 *certs);

/* HPKE's KEM, KDF and AEAD, for a sender (`sender` nonzero) or a
   recipient. */
int peios_policy_hpke(const struct evp_hpke_kem_st *kem, const struct evp_hpke_kdf_st *kdf,
                      const struct evp_hpke_aead_st *aead, int sender);
int peios_policy_hpke_kem(const struct evp_hpke_kem_st *kem, enum peios_operation op);

/* Calls that are checked by what they produce or accept, which AWS-LC's
   API gives no way to know first: each calls AWS-LC itself. A generated
   key or parameters policy refuses are freed, as AWS-LC frees them when it
   fails. A certificate chain AWS-LC accepts is refused if policy refuses
   any signature in it, or any key that checked one. */
/* The check for the algorithm algorithms.toml names `name`, `tls12` say,
   for `op`; and a refusal reported again, for a call on a connection
   already refused. */
int peios_policy_name(const char *name, enum peios_operation op);
void peios_policy_refused(void);

/* Each signature in a verified certificate chain, leaf first: each
   certificate's, checked with its issuer's key. The last is the trust
   anchor, whose own signature isn't checked. */
int peios_policy_chain(const struct stack_st_X509 *chain);

int peios_policy_keygen(struct evp_pkey_ctx_st *ctx, struct evp_pkey_st **out_pkey);
int peios_policy_keygen_deterministic(struct evp_pkey_ctx_st *ctx, struct evp_pkey_st **out_pkey,
                                      const unsigned char *seed, size_t *seed_len);
int peios_policy_paramgen(struct evp_pkey_ctx_st *ctx, struct evp_pkey_st **out_pkey);
int peios_policy_verify_cert(struct x509_store_ctx_st *ctx);

/* TLS, in libpssl: the calls that can run or finish a handshake, each of
   which checks what the handshake negotiated once it's finished, and
   fails the connection, with an insufficient_security alert, if policy
   refuses any of it. A refused connection fails every later call too. */
struct ssl_st;
int peios_tls_do_handshake(struct ssl_st *ssl);
int peios_tls_connect(struct ssl_st *ssl);
int peios_tls_accept(struct ssl_st *ssl);
int peios_tls_read(struct ssl_st *ssl, void *buf, int num);
int peios_tls_read_ex(struct ssl_st *ssl, void *buf, size_t num, size_t *read_bytes);
int peios_tls_peek(struct ssl_st *ssl, void *buf, int num);
int peios_tls_peek_ex(struct ssl_st *ssl, void *buf, size_t num, size_t *read_bytes);
int peios_tls_write(struct ssl_st *ssl, const void *buf, int num);
int peios_tls_write_ex(struct ssl_st *ssl, const void *buf, size_t num, size_t *written);

/* Ends the process, for a refused call to `function`, which can't report
   failure: it returns nothing, or nothing its callers check, as with
   OpenSSL's `MD5_Init`. Carrying on would leave the caller using a
   context or output that was never computed. */
__attribute__((noreturn)) void peios_policy_abort(const char *function);

#define PEIOS_R_REFUSED_BY_POLICY 1000
#define PEIOS_R_UNGRADED_ALGORITHM 1001


#endif
