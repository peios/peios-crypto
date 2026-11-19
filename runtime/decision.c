/* The policy decision, kept apart from AWS-LC so that it can be tested
   alone with any policy. */
#include "peios_policy.h"

enum peios_decision peios_policy_decision(const struct peios_algorithm *algorithm,
                                          const struct peios_policy *policy) {
    if (algorithm->floor) {
        return PEIOS_REJECT;
    }
    if (algorithm->grade < policy->reject_below ||
        (policy->reject_non_fips && !algorithm->fips)) {
        return PEIOS_REJECT;
    }
    if (algorithm->grade < policy->warn_below || (policy->warn_non_fips && !algorithm->fips)) {
        return PEIOS_WARN;
    }
    return PEIOS_ALLOW;
}
