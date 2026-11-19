// The policy decision alone, with policies the installed libraries never
// run under: tightened grades and FIPS.

#include <stdio.h>

#include "peios_policy.h"

static int failures = 0;

static void expect(const struct peios_algorithm *algorithm, const struct peios_policy *policy,
                   enum peios_decision want, const char *what) {
    if (peios_policy_decision(algorithm, policy) != want) {
        fprintf(stderr, "decision_test: %s\n", what);
        failures++;
    }
}

int main(void) {
    const struct peios_algorithm md5 = {.id = "md5.digest", .grade = PEIOS_GRADE_U, .fips = 0};
    const struct peios_algorithm sha1_hmac = {.id = "sha1.hmac", .grade = PEIOS_GRADE_C, .fips = 1};
    const struct peios_algorithm aes = {.id = "aes-256-gcm.encrypt", .grade = PEIOS_GRADE_A, .fips = 1};
    const struct peios_algorithm chacha = {.id = "chacha20.encrypt", .grade = PEIOS_GRADE_A, .fips = 0};
    const struct peios_algorithm null_cipher = {.id = "enc-null.encrypt", .grade = PEIOS_GRADE_A, .floor = 1};

    const struct peios_policy defaults = {.reject_below = PEIOS_GRADE_U, .warn_below = PEIOS_GRADE_C};
    expect(&md5, &defaults, PEIOS_WARN, "MD5 under the defaults isn't warned about");
    expect(&sha1_hmac, &defaults, PEIOS_ALLOW, "HMAC-SHA-1 under the defaults isn't allowed");
    expect(&null_cipher, &defaults, PEIOS_REJECT, "the floor isn't refused under the defaults");

    const struct peios_policy reject_below_b = {.reject_below = PEIOS_GRADE_B, .warn_below = PEIOS_GRADE_A};
    expect(&md5, &reject_below_b, PEIOS_REJECT, "MD5 isn't refused below B");
    expect(&sha1_hmac, &reject_below_b, PEIOS_REJECT, "grade C isn't refused below B");
    expect(&aes, &reject_below_b, PEIOS_ALLOW, "grade A is refused below B");

    const struct peios_policy fips = {.reject_below = PEIOS_GRADE_U, .warn_below = PEIOS_GRADE_U, .reject_non_fips = 1};
    expect(&chacha, &fips, PEIOS_REJECT, "ChaCha20 isn't refused under FIPS");
    expect(&aes, &fips, PEIOS_ALLOW, "AES isn't allowed under FIPS");

    const struct peios_policy warn_fips = {.reject_below = PEIOS_GRADE_U, .warn_below = PEIOS_GRADE_U, .warn_non_fips = 1};
    expect(&chacha, &warn_fips, PEIOS_WARN, "ChaCha20 isn't warned about when warning on FIPS");

    const struct peios_policy open = {.reject_below = PEIOS_GRADE_U, .warn_below = PEIOS_GRADE_U};
    expect(&null_cipher, &open, PEIOS_REJECT, "the floor isn't refused under the loosest policy");

    if (failures == 0) {
        puts("decision_test: ok");
    }
    return failures != 0;
}
