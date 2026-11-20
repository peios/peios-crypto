// The machine's crypto policy as a process sees it: read from cryptod's
// policy file, falling back to Peios's defaults; thresholds and exceptions
// applied; and what policy warns about, and each exception's use, reported
// to cryptod once per process. Each case runs in a child of its own, as the
// policy is read once per process, against the testing libpcrypto, which
// takes the policy's path, its copy's SDDL, the exceptions the process may
// use and the report socket from the environment.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define REFUSED_BY_POLICY 1000
#define POLICY "/tmp/policy-case/policy"
#define REPORTS "/tmp/policy-case/report"
#define CRYPTOD_SID "S-1-5-80-2691053820-547492864-353945177-641201782-1210658655"

enum { GRADE_U, GRADE_D, GRADE_C, GRADE_B, GRADE_A };
enum { REJECT_NON_FIPS = 1, WARN_NON_FIPS = 2, EXCEPTIONS_MAY_REJECT = 4 };
enum { REPORT_WARNED = 1, REPORT_EXCEPTION = 2, REPORT_POLICY = 3 };
enum { PROBLEM_INSECURE = 2, PROBLEM_MALFORMED = 3, PROBLEM_VERSION = 4 };

static int failures = 0;

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "machine_policy: %s\n", what);
        failures++;
    }
}

// A policy file, version 1, built a field at a time.
struct file {
    uint8_t data[4096];
    size_t len;
};

static void u8(struct file *f, unsigned v) {
    f->data[f->len++] = (uint8_t)v;
}

static void u16(struct file *f, unsigned v) {
    u8(f, v >> 8);
    u8(f, v & 0xff);
}

static void str8(struct file *f, const char *s) {
    u8(f, (unsigned)strlen(s));
    memcpy(f->data + f->len, s, strlen(s));
    f->len += strlen(s);
}

static void header(struct file *f, unsigned version, unsigned reject, unsigned warn,
                   unsigned flags, unsigned exceptions) {
    f->len = 0;
    memcpy(f->data, "PEIOSCPL", 8);
    f->len = 8;
    u16(f, version);
    u8(f, reject);
    u8(f, warn);
    u8(f, flags);
    u16(f, exceptions);
}

// An exception for one id. The testing library decides ProgramSecurity by
// name, so the SD is a placeholder.
static void exception(struct file *f, const char *name, int warn, const char *id) {
    str8(f, name);
    u8(f, warn);
    u16(f, 2);
    u8(f, 0);
    u8(f, 0);
    u16(f, 1);
    str8(f, id);
}

static void write_policy(const struct file *f) {
    FILE *out = fopen(POLICY, "wb");
    fwrite(f->data, 1, f->len, out);
    fclose(out);
}

// What a case's child reported.
struct reports {
    int count;
    struct {
        int kind, problem;
        char id[256], name[256];
    } r[32];
};

static int listener;

static void drain(struct reports *out) {
    memset(out, 0, sizeof(*out));
    for (;;) {
        int conn = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (conn < 0) {
            return;
        }
        uint8_t msg[600];
        ssize_t n = recv(conn, msg, sizeof(msg), 0);
        close(conn);
        if (n < 4 || out->count == 32) {
            continue;
        }
        size_t at = 2, id_len = msg[at++];
        if (at + id_len + 1 > (size_t)n) {
            continue;
        }
        int i = out->count++;
        out->r[i].kind = msg[0];
        out->r[i].problem = msg[1];
        memcpy(out->r[i].id, msg + at, id_len);
        at += id_len;
        size_t name_len = msg[at++];
        if (at + name_len <= (size_t)n) {
            memcpy(out->r[i].name, msg + at, name_len);
        }
    }
}

static int reported(const struct reports *r, int kind, const char *id, const char *name) {
    int n = 0;
    for (int i = 0; i < r->count; i++) {
        n += r->r[i].kind == kind && strcmp(r->r[i].id, id) == 0 &&
             (name == NULL || strcmp(r->r[i].name, name) == 0);
    }
    return n;
}

static int problem_reported(const struct reports *r, int problem) {
    for (int i = 0; i < r->count; i++) {
        if (r->r[i].kind == REPORT_POLICY && r->r[i].problem == problem) {
            return 1;
        }
    }
    return 0;
}

// Whether a digest with `md` is allowed, in the child.
static int digest_allowed(const EVP_MD *md) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ERR_clear_error();
    int ok = EVP_DigestInit_ex(ctx, md, NULL);
    uint32_t error = ERR_peek_last_error();
    EVP_MD_CTX_free(ctx);
    if (ok) {
        return 1;
    }
    return ERR_GET_LIB(error) == ERR_LIB_USER && ERR_GET_REASON(error) == REFUSED_BY_POLICY ? 0 : -1;
}

// Runs `child` in a child of its own, with `granted` as the exceptions it
// may use (NULL for none set) and `sddl` as its policy copy's SDDL, then
// collects what it reported. Returns whether the child's checks held.
static int run(int (*child)(void), const char *granted, const char *sddl, struct reports *out) {
    pid_t pid = fork();
    if (pid == 0) {
        setenv("PEIOS_CRYPTO_TEST_POLICY", POLICY, 1);
        setenv("PEIOS_CRYPTO_TEST_REPORT", REPORTS, 1);
        setenv("PEIOS_CRYPTO_TEST_GRANTED", granted != NULL ? granted : "", 1);
        if (sddl != NULL) {
            setenv("PEIOS_CRYPTO_TEST_POLICY_SDDL", sddl, 1);
        }
        _exit(child() ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    drain(out);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// MD5 (U) is allowed and warned about, once however often it's used;
// SHA-256 (B) isn't warned about.
static int defaults_child(void) {
    return digest_allowed(EVP_md5()) == 1 && digest_allowed(EVP_md5()) == 1 &&
           digest_allowed(EVP_sha256()) == 1;
}

static int md5_refused_child(void) {
    return digest_allowed(EVP_md5()) == 0 && digest_allowed(EVP_sha256()) == 1;
}

static int md5_allowed_child(void) {
    return digest_allowed(EVP_md5()) == 1 && digest_allowed(EVP_md5()) == 1;
}

// A forked child reports again for itself.
static int forked_child(void) {
    if (digest_allowed(EVP_md5()) != 1) {
        return 0;
    }
    pid_t pid = fork();
    if (pid == 0) {
        _exit(digest_allowed(EVP_md5()) == 1 ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int null_cipher_refused_child(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_EncryptInit_ex(ctx, EVP_enc_null(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_free(ctx);
    return !ok;
}

int main(void) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strcpy(addr.sun_path, REPORTS);
    mkdir("/tmp/policy-case", 0700);
    unlink(REPORTS);
    listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 64) != 0) {
        perror("machine_policy: report socket");
        return 1;
    }
    struct file f;
    struct reports r;

    // No policy: Peios's defaults, warn below C, reject only the floor.
    unlink(POLICY);
    check(run(defaults_child, NULL, NULL, &r), "without a policy, MD5 or SHA-256 was refused");
    check(reported(&r, REPORT_WARNED, "md5.digest", NULL) == 1,
          "without a policy, MD5 wasn't warned about exactly once");
    check(reported(&r, REPORT_WARNED, "sha256.digest", NULL) == 0, "SHA-256 was warned about");

    // Reject below C.
    header(&f, 1, GRADE_C, GRADE_B, EXCEPTIONS_MAY_REJECT, 0);
    write_policy(&f);
    check(run(md5_refused_child, NULL, NULL, &r), "rejecting below C didn't refuse MD5 alone");

    // An exception for MD5, which the process may use: allowed, its use
    // reported once, and not warned about.
    header(&f, 1, GRADE_C, GRADE_B, EXCEPTIONS_MAY_REJECT, 1);
    exception(&f, "Test.Md5", 0, "md5.digest");
    write_policy(&f);
    check(run(md5_allowed_child, "Test.Md5", NULL, &r), "an exception didn't allow MD5");
    check(reported(&r, REPORT_EXCEPTION, "md5.digest", "Test.Md5") == 1,
          "an exception's use wasn't reported exactly once");
    check(reported(&r, REPORT_WARNED, "md5.digest", NULL) == 0,
          "MD5 was warned about under an exception that doesn't warn");
    check(run(md5_refused_child, "Other.Exception", NULL, &r),
          "an exception the process may not use allowed MD5");
    check(run(forked_child, "Test.Md5", NULL, &r) &&
              reported(&r, REPORT_EXCEPTION, "md5.digest", "Test.Md5") == 2,
          "a forked child didn't report its own use of an exception");

    // An exception that warns is reported as used and warned about.
    header(&f, 1, GRADE_C, GRADE_B, EXCEPTIONS_MAY_REJECT, 1);
    exception(&f, "Test.Md5", 1, "md5.digest");
    write_policy(&f);
    check(run(md5_allowed_child, "Test.Md5", NULL, &r) &&
              reported(&r, REPORT_EXCEPTION, "md5.digest", "Test.Md5") == 1 &&
              reported(&r, REPORT_WARNED, "md5.digest", NULL) == 1,
          "an exception that warns wasn't reported as used and warned about");

    // Exceptions that may only affect warnings don't allow what's rejected.
    header(&f, 1, GRADE_C, GRADE_B, 0, 1);
    exception(&f, "Test.Md5", 0, "md5.digest");
    write_policy(&f);
    check(run(md5_refused_child, "Test.Md5", NULL, &r),
          "an exception allowed MD5 when exceptions may not affect rejection");

    // Nothing excepts the floor.
    header(&f, 1, GRADE_U, GRADE_C, EXCEPTIONS_MAY_REJECT, 1);
    exception(&f, "Test.Null", 0, "enc-null.encrypt");
    write_policy(&f);
    check(run(null_cipher_refused_child, "Test.Null", NULL, &r),
          "an exception allowed the null cipher");

    // FIPS: rejecting non-approved algorithms refuses MD5 at any grade.
    header(&f, 1, GRADE_U, GRADE_U, REJECT_NON_FIPS, 0);
    write_policy(&f);
    check(run(md5_refused_child, NULL, NULL, &r), "rejecting non-FIPS algorithms didn't refuse MD5");

    // A policy that can't be used falls back to the defaults, reported.
    header(&f, 2, GRADE_C, GRADE_B, 0, 0);
    write_policy(&f);
    check(run(defaults_child, NULL, NULL, &r) && problem_reported(&r, PROBLEM_VERSION),
          "a policy of an unknown version wasn't reported and replaced by the defaults");
    header(&f, 1, GRADE_C, GRADE_B, 0, 1);
    write_policy(&f);
    check(run(defaults_child, NULL, NULL, &r) && problem_reported(&r, PROBLEM_MALFORMED),
          "a truncated policy wasn't reported and replaced by the defaults");
    header(&f, 1, 9, GRADE_B, 0, 0);
    write_policy(&f);
    check(run(defaults_child, NULL, NULL, &r) && problem_reported(&r, PROBLEM_MALFORMED),
          "a policy with an unknown grade wasn't reported and replaced by the defaults");

    // A copy anyone could change isn't used; one only SYSTEM or cryptod
    // could is.
    header(&f, 1, GRADE_C, GRADE_B, 0, 0);
    write_policy(&f);
    check(run(defaults_child, NULL, "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;WD)", &r) &&
              problem_reported(&r, PROBLEM_INSECURE),
          "a policy everyone may write was used");
    check(run(defaults_child, NULL, "O:WDG:SYD:(A;;FA;;;SY)", &r) &&
              problem_reported(&r, PROBLEM_INSECURE),
          "a policy owned by Everyone was used");
    check(run(defaults_child, NULL, "O:SYG:SY", &r) && problem_reported(&r, PROBLEM_INSECURE),
          "a policy with no DACL was used");
    check(run(md5_refused_child, NULL, "O:SYG:SYD:(A;;FA;;;SY)(A;;FR;;;WD)", &r),
          "a policy only SYSTEM may write wasn't used");
    check(run(md5_refused_child, NULL,
              "O:" CRYPTOD_SID "G:SYD:(A;;FA;;;" CRYPTOD_SID ")(A;;FR;;;WD)(A;OICIIO;FA;;;WD)",
              &r),
          "a policy only cryptod may write, with an inherit-only entry, wasn't used");

    unlink(POLICY);
    unlink(REPORTS);
    if (failures == 0) {
        puts("machine_policy: ok");
    }
    return failures != 0;
}
