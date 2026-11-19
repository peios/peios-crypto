/* The policy runtime's checks, which the generated hooks call. Compiled
   against AWS-LC's prefixed headers, so that it calls AWS-LC directly
   rather than through libpcrypto's own hooks.

   Until the runtime reads the machine's policy, it applies Peios's
   defaults: nothing above the floor is refused, grades below C are warned
   about, and FIPS is off. Warnings aren't reported yet. */
#include <stdio.h>
#include <stdlib.h>

#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/err.h>

#include "peios_policy.h"

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

int peios_policy_algorithm(const struct peios_algorithm *algorithm) {
    return decide(algorithm);
}

void peios_policy_abort(const char *function) {
    fprintf(stderr,
            "libpcrypto: Peios crypto policy refused %s, which can't report failure; "
            "ending the process\n",
            function);
    abort();
}

int peios_policy_rsa_keygen(int bits) {
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const struct peios_algorithm *a = &peios_algorithms[i];
        if (a->kind == PEIOS_KIND_RSA && a->op == PEIOS_OP_KEYGEN && bits >= a->min_bits &&
            bits <= a->max_bits) {
            return decide(a);
        }
    }
    return decide(NULL);
}
