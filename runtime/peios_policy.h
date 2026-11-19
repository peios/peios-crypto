/* Peios crypto policy runtime: the interface between libpcrypto's
   generated hooks and policy table, and the runtime that decides. Nothing
   here is exported: the version scripts keep every peios_ name local. */
#ifndef PEIOS_POLICY_H
#define PEIOS_POLICY_H

#pragma GCC visibility push(hidden)

struct env_md_st;
struct evp_cipher_st;
struct evp_cipher_ctx_st;
struct evp_aead_st;

/* What an algorithms.toml entry grades. */
enum peios_kind {
    PEIOS_KIND_DIGEST,
    PEIOS_KIND_CIPHER,
    PEIOS_KIND_AEAD,
    PEIOS_KIND_RSA,
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
    PEIOS_OP_ENCRYPT,
    PEIOS_OP_DECRYPT,
    PEIOS_OP_KEYGEN,
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
    enum peios_kind kind;
    const struct env_md_st *(*md)(void);
    const struct evp_cipher_st *(*cipher)(void);
    const struct evp_aead_st *(*aead)(void);
    int min_bits;
    int max_bits;
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

/* Ends the process, for a refused call to `function`, which can't report
   failure: it returns nothing, or nothing its callers check, as with
   OpenSSL's `MD5_Init`. Carrying on would leave the caller using a
   context or output that was never computed. */
__attribute__((noreturn)) void peios_policy_abort(const char *function);

#define PEIOS_R_REFUSED_BY_POLICY 1000
#define PEIOS_R_UNGRADED_ALGORITHM 1001

#pragma GCC visibility pop

#endif
