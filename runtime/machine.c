/* The machine's crypto policy, as this process sees it: the policy cryptod
   compiles from Machine\System\Cryptography, and the exceptions this
   process's primary token may use (PEI-1721). Loaded once, at the first
   decision, and kept: a policy that changes applies to processes started
   after it.

   The policy is read from cryptod's current copy, then from the copy it
   keeps across reboots, then, if neither exists, Peios's defaults. A copy
   that can't be read, that anyone but SYSTEM or cryptod could write, or
   that isn't a policy is skipped, and reported.

   What policy warns about, and each exception's use, is reported to
   cryptod once per process, which records it: most processes can't emit
   events themselves. A report is one datagram, sent without waiting; one
   that can't be sent, before cryptod is listening say, is lost.

   Compiled against AWS-LC's prefixed headers and libpeios's. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/bytestring.h>

#include <peios/access.h>
#include <peios/file.h>
#include <peios/security.h>
#include <peios/token.h>

#include "peios_policy.h"

/* The policy's two copies, cryptod's report socket, and the largest
   policy read. */
#define POLICY_CURRENT "/run/cryptod/policy"
#define POLICY_LAST_KNOWN "/var/state/cryptod/policy"
#define REPORT_SOCKET "/run/cryptod/report"
#define POLICY_MAX (1u << 20)

/* cryptod's service SID: S-1-5-80 and the SHA-1 of "CRYPTOD" in UTF-16LE,
   as five little-endian sub-authorities, the platform's rule. */
#define CRYPTOD_SID "S-1-5-80-2691053820-547492864-353945177-641201782-1210658655"

/* The right an exception's ProgramSecurity grants a program to use it. */
#define EXCEPTION_USE 0x0001u

/* The policy file, version 1 (Learn: the cryptod reference):

     "PEIOSCPL"          magic
     u16                 version, 1
     u8 u8               reject_below, warn_below: 0 (U) to 4 (A)
     u8                  flags: POLICY_*
     u16                 exception count, then each exception:
       u8-prefixed       its name, Owner.Purpose
       u8                flags: EXCEPTION_WARN
       u16-prefixed      ProgramSecurity, a self-relative SD
       u16               id count, then each u8-prefixed id, md5.hmac say

   Integers are big-endian. cryptod resolves Enabled, WarnByDefault and
   WarnAlways as it compiles, so the file holds what applies. */
#define POLICY_MAGIC "PEIOSCPL"
#define POLICY_VERSION 1
#define POLICY_REJECT_NON_FIPS 0x01u
#define POLICY_WARN_NON_FIPS 0x02u
#define POLICY_EXCEPTIONS_MAY_REJECT 0x04u
#define EXCEPTION_WARN 0x01u

/* What a report is: a use policy warns about, an exception's use, or a
   policy that couldn't be read, with what was wrong. */
enum report_kind { REPORT_WARNED = 1, REPORT_EXCEPTION = 2, REPORT_POLICY = 3 };
enum policy_problem {
    PROBLEM_NONE = 0,
    PROBLEM_UNREADABLE = 1,
    PROBLEM_INSECURE = 2,
    PROBLEM_MALFORMED = 3,
    PROBLEM_VERSION = 4,
    PROBLEM_TOKEN = 5,
};

struct exception {
    char name[256];
    int warn;
    int reported;
};

struct machine {
    struct peios_policy policy;
    int exceptions_may_reject;
    unsigned exception_count;
    struct exception *exceptions;
    /* For each entry, the exception this process may use for it, or -1;
       and whether its warning has been reported. NULL if they couldn't be
       allocated: nothing is excepted, or reported. */
    int16_t *excepted;
    unsigned char *warned;
};

static struct machine machine = {
    .policy =
        {
            .reject_below = PEIOS_GRADE_U,
            .warn_below = PEIOS_GRADE_C,
            .reject_non_fips = 0,
            .warn_non_fips = 0,
        },
    .exceptions_may_reject = 1,
};
static pthread_once_t loaded = PTHREAD_ONCE_INIT;

#ifdef PEIOS_TESTING
/* The testing libraries take what a test sets, in place of the machine's:
   the policy's path, the SDDL its copy has, the exceptions the process may
   use, by name, comma-separated, and the report socket. */
static const char *testing(const char *name, const char *otherwise) {
    const char *value = getenv(name);
    return value != NULL ? value : otherwise;
}
#define TESTING(name, otherwise) testing(name, otherwise)
#else
#define TESTING(name, otherwise) (otherwise)
#endif

/* Sends cryptod one report, without waiting, and without disturbing errno.
   `id` is the entry's, `exception` the exception's name, either "". */
static void report(enum report_kind kind, enum policy_problem problem, const char *id,
                   const char *exception) {
    int saved = errno;
    size_t id_len = strnlen(id, 255), name_len = strnlen(exception, 255);
    uint8_t msg[4 + 255 + 255];
    size_t n = 0;
    msg[n++] = (uint8_t)kind;
    msg[n++] = (uint8_t)problem;
    msg[n++] = (uint8_t)id_len;
    memcpy(msg + n, id, id_len);
    n += id_len;
    msg[n++] = (uint8_t)name_len;
    memcpy(msg + n, exception, name_len);
    n += name_len;
    const char *path = TESTING("PEIOS_CRYPTO_TEST_REPORT", REPORT_SOCKET);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    int s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s >= 0 && strlen(path) < sizeof(addr.sun_path)) {
        strcpy(addr.sun_path, path);
        if (connect(s, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
            send(s, msg, n, MSG_NOSIGNAL | MSG_DONTWAIT);
        }
    }
    if (s >= 0) {
        close(s);
    }
    errno = saved;
}

/* Rights a DACL entry could give someone to change the policy. */
#define CHANGING                                                                     \
    (KACS_FILE_WRITE_DATA | KACS_FILE_APPEND_DATA | KACS_FILE_WRITE_EA |              \
     KACS_FILE_WRITE_ATTRIBUTES | KACS_ACCESS_DELETE | KACS_ACCESS_WRITE_DAC |        \
     KACS_ACCESS_WRITE_OWNER | KACS_ACCESS_GENERIC_WRITE | KACS_ACCESS_GENERIC_ALL |  \
     KACS_ACCESS_MAXIMUM_ALLOWED)

static int is_sid(const void *sid, size_t len, const uint8_t *want, size_t want_len) {
    return peios_sid_equal(sid, len, want, want_len);
}

/* Whether a policy copy with security descriptor `sd` can be trusted: its
   owner is SYSTEM or cryptod, and its DACL lets no one else change it. */
static int sd_trusted(const void *sd, size_t sd_len) {
    uint8_t system[68], cryptod[68];
    ssize_t system_len = peios_sid_well_known(system, sizeof(system), PEIOS_WKS_SYSTEM);
    ssize_t cryptod_len = peios_sid_parse_string(cryptod, sizeof(cryptod), CRYPTOD_SID);
    peios_sd_view view;
    const void *owner;
    size_t owner_len;
    peios_acl_view dacl;
    if (system_len < 0 || cryptod_len < 0 || peios_sd_parse(sd, sd_len, &view) != 0 ||
        peios_sd_view_owner(&view, &owner, &owner_len) != 0 ||
        !(is_sid(owner, owner_len, system, (size_t)system_len) ||
          is_sid(owner, owner_len, cryptod, (size_t)cryptod_len)) ||
        peios_sd_view_dacl(&view, &dacl) != 0) {
        /* No owner, someone else's, or no DACL, which lets everyone in. */
        return 0;
    }
    for (unsigned i = 0; i < peios_acl_view_count(&dacl); i++) {
        peios_ace_view ace;
        const void *sid;
        size_t sid_len;
        if (peios_acl_view_ace(&dacl, i, &ace) != 0) {
            return 0;
        }
        uint8_t type = peios_ace_view_type(&ace);
        if (type == KACS_ACE_TYPE_ACCESS_DENIED || type == KACS_ACE_TYPE_ACCESS_DENIED_OBJECT ||
            type == KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK ||
            type == KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT ||
            (peios_ace_view_flags(&ace) & KACS_ACE_FLAG_INHERIT_ONLY) ||
            !(peios_ace_view_mask(&ace) & CHANGING)) {
            continue;
        }
        if (peios_ace_view_sid(&ace, &sid, &sid_len) != 0 ||
            !(is_sid(sid, sid_len, system, (size_t)system_len) ||
              is_sid(sid, sid_len, cryptod, (size_t)cryptod_len))) {
            return 0;
        }
    }
    return 1;
}

/* Whether the open copy at `fd` can be trusted: whether only SYSTEM and
   cryptod could have written it. */
static int trusted(int fd) {
#ifdef PEIOS_TESTING
    const char *sddl = getenv("PEIOS_CRYPTO_TEST_POLICY_SDDL");
    if (sddl != NULL) {
        uint8_t sd[1024];
        ssize_t len = peios_sddl_parse_sd(sd, sizeof(sd), sddl);
        return len > 0 && sd_trusted(sd, (size_t)len);
    }
    if (getenv("PEIOS_CRYPTO_TEST_POLICY") != NULL) {
        return 1;
    }
#endif
    uint8_t sd[4096];
    ssize_t len = peios_fd_get_sd(fd, KACS_SECINFO_OWNER | KACS_SECINFO_DACL, sd, sizeof(sd));
    return len > 0 && sd_trusted(sd, (size_t)len);
}

/* Whether this process may use the exception `name` whose ProgramSecurity
   is `sd`, checked against its primary token, `token`; impersonation is
   deliberately not followed. */
static int granted(int token, const char *name, const uint8_t *sd, size_t sd_len) {
#ifdef PEIOS_TESTING
    const char *names = getenv("PEIOS_CRYPTO_TEST_GRANTED");
    if (names != NULL) {
        size_t len = strlen(name);
        for (const char *p = names; *p != '\0';) {
            const char *end = strchr(p, ',');
            size_t n = end != NULL ? (size_t)(end - p) : strlen(p);
            if (n == len && strncmp(p, name, n) == 0) {
                return 1;
            }
            p += n + (end != NULL);
        }
        return 0;
    }
#endif
    (void)name;
    struct peios_access_request request = {
        .token_fd = token,
        .sd = sd,
        .sd_len = sd_len,
        .desired = EXCEPTION_USE,
        .mapping = {.read = 0, .write = 0, .execute = EXCEPTION_USE, .all = EXCEPTION_USE},
    };
    uint32_t rights = 0;
    return token >= 0 && peios_access_check(&request, &rights, NULL) == 0;
}

static int entry_index(const CBS *id) {
    for (unsigned i = 0; i < peios_algorithm_count; i++) {
        const char *entry = peios_algorithms[i].id;
        if (strlen(entry) == CBS_len(id) && memcmp(entry, CBS_data(id), CBS_len(id)) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Reads the policy in `in` into `m`, which the caller has zeroed and given
   an `excepted` table of -1s. Nothing of a policy that fails to read is
   used. */
static enum policy_problem parse(CBS in, struct machine *m) {
    CBS magic, copy;
    uint16_t version, count;
    uint8_t reject, warn, flags;
    if (!CBS_get_bytes(&in, &magic, 8) || !CBS_mem_equal(&magic, (const uint8_t *)POLICY_MAGIC, 8) ||
        !CBS_get_u16(&in, &version)) {
        return PROBLEM_MALFORMED;
    }
    if (version != POLICY_VERSION) {
        return PROBLEM_VERSION;
    }
    if (!CBS_get_u8(&in, &reject) || !CBS_get_u8(&in, &warn) || !CBS_get_u8(&in, &flags) ||
        reject > PEIOS_GRADE_A || warn > PEIOS_GRADE_A || !CBS_get_u16(&in, &count)) {
        return PROBLEM_MALFORMED;
    }
    /* A first pass checks the whole file, so that none of a malformed one
       is used. */
    copy = in;
    for (unsigned i = 0; i < count; i++) {
        CBS name, sd, id;
        uint8_t exception_flags;
        uint16_t ids;
        if (!CBS_get_u8_length_prefixed(&copy, &name) || CBS_len(&name) == 0 ||
            !CBS_get_u8(&copy, &exception_flags) || !CBS_get_u16_length_prefixed(&copy, &sd) ||
            !CBS_get_u16(&copy, &ids)) {
            return PROBLEM_MALFORMED;
        }
        for (unsigned j = 0; j < ids; j++) {
            if (!CBS_get_u8_length_prefixed(&copy, &id)) {
                return PROBLEM_MALFORMED;
            }
        }
    }
    if (CBS_len(&copy) != 0) {
        return PROBLEM_MALFORMED;
    }
    m->policy.reject_below = reject;
    m->policy.warn_below = warn;
    m->policy.reject_non_fips = (flags & POLICY_REJECT_NON_FIPS) != 0;
    m->policy.warn_non_fips = (flags & POLICY_WARN_NON_FIPS) != 0;
    m->exceptions_may_reject = (flags & POLICY_EXCEPTIONS_MAY_REJECT) != 0;
    if (count == 0) {
        return PROBLEM_NONE;
    }
    if (m->excepted == NULL || (m->exceptions = calloc(count, sizeof(*m->exceptions))) == NULL) {
        return PROBLEM_NONE;
    }
    m->exception_count = count;
#ifdef PEIOS_TESTING
    int token = getenv("PEIOS_CRYPTO_TEST_GRANTED") != NULL
                    ? -1
                    : peios_token_open_self(KACS_TOKEN_OPEN_REAL, KACS_TOKEN_QUERY);
#else
    int token = peios_token_open_self(KACS_TOKEN_OPEN_REAL, KACS_TOKEN_QUERY);
#endif
    if (token < 0) {
        report(REPORT_POLICY, PROBLEM_TOKEN, "", "");
    }
    for (unsigned i = 0; i < count; i++) {
        CBS name, sd, id;
        uint8_t exception_flags;
        uint16_t ids;
        CBS_get_u8_length_prefixed(&in, &name);
        CBS_get_u8(&in, &exception_flags);
        CBS_get_u16_length_prefixed(&in, &sd);
        CBS_get_u16(&in, &ids);
        struct exception *e = &m->exceptions[i];
        memcpy(e->name, CBS_data(&name), CBS_len(&name));
        e->warn = (exception_flags & EXCEPTION_WARN) != 0;
        int use = granted(token, e->name, CBS_data(&sd), CBS_len(&sd));
        for (unsigned j = 0; j < ids; j++) {
            CBS_get_u8_length_prefixed(&in, &id);
            int k = entry_index(&id);
            /* An entry this library doesn't grade excepts nothing, and
               nothing excepts the floor. */
            if (use && k >= 0 && !peios_algorithms[k].floor && m->excepted[k] < 0) {
                m->excepted[k] = (int16_t)i;
            }
        }
    }
    if (token >= 0) {
        close(token);
    }
    return PROBLEM_NONE;
}

/* Reads the copy at `path` into `m`: 1 if it was the policy, 0 if there's
   no such copy, -1 if there's one that couldn't be used, reported. */
static int read_copy(const char *path, struct machine *m) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            return 0;
        }
        report(REPORT_POLICY, PROBLEM_UNREADABLE, "", "");
        return -1;
    }
    enum policy_problem problem = PROBLEM_NONE;
    uint8_t *data = NULL;
    size_t len = 0;
    if (!trusted(fd)) {
        problem = PROBLEM_INSECURE;
    } else if ((data = malloc(POLICY_MAX)) == NULL) {
        problem = PROBLEM_UNREADABLE;
    } else {
        for (;;) {
            ssize_t n = read(fd, data + len, POLICY_MAX - len);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 || (n > 0 && len + (size_t)n == POLICY_MAX)) {
                problem = n < 0 ? PROBLEM_UNREADABLE : PROBLEM_MALFORMED;
                break;
            }
            if (n == 0) {
                break;
            }
            len += (size_t)n;
        }
    }
    close(fd);
    if (problem == PROBLEM_NONE) {
        CBS in;
        CBS_init(&in, data, len);
        problem = parse(in, m);
    }
    free(data);
    if (problem != PROBLEM_NONE) {
        report(REPORT_POLICY, problem, "", "");
        return -1;
    }
    return 1;
}

/* The process the reports so far were for. A forked child is another
   process, and reports for itself. */
static pid_t reporting_pid;
static pthread_mutex_t reporting_lock = PTHREAD_MUTEX_INITIALIZER;

static void forget_reports_if_forked(void) {
    pid_t now = getpid();
    if (__atomic_load_n(&reporting_pid, __ATOMIC_ACQUIRE) == now) {
        return;
    }
    pthread_mutex_lock(&reporting_lock);
    if (reporting_pid != now) {
        if (machine.warned != NULL) {
            memset(machine.warned, 0, peios_algorithm_count);
        }
        for (unsigned i = 0; i < machine.exception_count; i++) {
            machine.exceptions[i].reported = 0;
        }
        __atomic_store_n(&reporting_pid, now, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&reporting_lock);
}

static void load(void) {
    const char *copies[] = {
        TESTING("PEIOS_CRYPTO_TEST_POLICY", POLICY_CURRENT),
        TESTING("PEIOS_CRYPTO_TEST_POLICY", POLICY_LAST_KNOWN),
    };
    int16_t *excepted = malloc(peios_algorithm_count * sizeof(*excepted));
    machine.warned = calloc(peios_algorithm_count, 1);
    for (unsigned c = 0; c < sizeof(copies) / sizeof(copies[0]); c++) {
        if (c > 0 && strcmp(copies[c], copies[c - 1]) == 0) {
            break;
        }
        struct machine candidate = machine;
        candidate.exceptions = NULL;
        candidate.exception_count = 0;
        candidate.excepted = excepted;
        if (excepted != NULL) {
            for (unsigned i = 0; i < peios_algorithm_count; i++) {
                excepted[i] = -1;
            }
        }
        int got = read_copy(copies[c], &candidate);
        if (got == 1) {
            machine = candidate;
            break;
        }
        free(candidate.exceptions);
    }
    if (machine.excepted == NULL) {
        free(excepted);
    }
    reporting_pid = getpid();
}

/* Reports `flag`'s first use only, whichever thread gets there first. */
static int first(int *flag) {
    return __atomic_exchange_n(flag, 1, __ATOMIC_RELAXED) == 0;
}

static void warned(const struct peios_algorithm *algorithm) {
    unsigned i = (unsigned)(algorithm - peios_algorithms);
    if (machine.warned != NULL &&
        __atomic_exchange_n(&machine.warned[i], 1, __ATOMIC_RELAXED) == 0) {
        report(REPORT_WARNED, PROBLEM_NONE, algorithm->id, "");
    }
}

int peios_machine_allows(const struct peios_algorithm *algorithm) {
    pthread_once(&loaded, load);
    enum peios_decision decision = peios_policy_decision(algorithm, &machine.policy);
    if (decision == PEIOS_ALLOW) {
        return 1;
    }
    unsigned i = (unsigned)(algorithm - peios_algorithms);
    struct exception *exception =
        machine.excepted != NULL && machine.excepted[i] >= 0 && !algorithm->floor
            ? &machine.exceptions[machine.excepted[i]]
            : NULL;
    if (decision == PEIOS_REJECT && (exception == NULL || !machine.exceptions_may_reject)) {
        return 0;
    }
    forget_reports_if_forked();
    if (exception != NULL) {
        /* Every process using an exception records it once, warned or
           not, so that an audit finds weak crypto in use. */
        if (first(&exception->reported)) {
            report(REPORT_EXCEPTION, PROBLEM_NONE, algorithm->id, exception->name);
        }
        if (!exception->warn) {
            return 1;
        }
    }
    warned(algorithm);
    return 1;
}

#ifdef PEIOS_TESTING
void peios_policy_testing_reject_below(enum peios_grade grade) {
    pthread_once(&loaded, load);
    machine.policy.reject_below = grade;
}
#endif
