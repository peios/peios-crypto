/* Peios crypto policy runtime: the interface between libpcrypto's
   generated hooks and policy table, and the runtime that decides. Nothing
   here is exported: the version scripts keep every peios_ name local. */
#ifndef PEIOS_POLICY_H
#define PEIOS_POLICY_H

#pragma GCC visibility push(hidden)

struct env_md_st;
struct evp_cipher_st;

/* What an algorithms.toml entry grades. */
enum peios_kind {
    PEIOS_KIND_DIGEST,
    PEIOS_KIND_CIPHER,
    PEIOS_KIND_RSA,
};

enum peios_operation {
    PEIOS_OP_DIGEST,
    PEIOS_OP_HMAC,
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
int peios_policy_rsa_keygen(int bits);

#define PEIOS_R_REFUSED_BY_POLICY 1000
#define PEIOS_R_UNGRADED_ALGORITHM 1001

#pragma GCC visibility pop

#endif
