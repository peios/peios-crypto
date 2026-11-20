// Data that names its own algorithm is checked where AWS-LC decrypts it,
// verifies it or keys its MAC, inside AWS-LC's own calls: PEM's legacy
// encryption, encrypted private keys, PKCS #12 files, PKCS #7 envelopes and
// signatures, OCSP responses and X.509 signatures. Each is made under
// Peios's default policy, which refuses only the floor, then read again
// under a stricter one, which the testing libpcrypto lets a test set: what
// it allows still reads, and what it refuses fails with Peios's error.

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs8.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define REFUSED_BY_POLICY 1000

// The testing libpcrypto's own: refuse grades below `grade`, U (0), D, C,
// B or A (4).
void peios_policy_testing_reject_below(int grade);
enum { GRADE_U, GRADE_D, GRADE_C, GRADE_B, GRADE_A };

static int failures = 0;

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "reading_policy: %s\n", what);
        ERR_print_errors_fp(stderr);
        failures++;
    }
    ERR_clear_error();
}

static int is_refusal(uint32_t error) {
    return ERR_GET_LIB(error) == ERR_LIB_USER && ERR_GET_REASON(error) == REFUSED_BY_POLICY;
}

// Whether the error queue holds Peios's refusal. A refusal inside one of
// AWS-LC's own calls is followed by the errors AWS-LC adds as it fails.
static int refused(void) {
    uint32_t error;
    int found = 0;
    while ((error = ERR_get_error()) != 0) {
        found |= is_refusal(error);
    }
    return found;
}

// Whether Peios's refusal is the last error, as a PEM read leaves it, and
// a check made before AWS-LC is called.
static int refused_last(void) {
    return is_refusal(ERR_peek_last_error());
}

static BIO *mem_of(BIO *from) {
    const uint8_t *data;
    size_t len;
    BIO_mem_contents(from, &data, &len);
    return BIO_new_mem_buf(data, (ossl_ssize_t)len);
}

int main(void) {
    // An RSA-2048 key, whose signatures and decryption are graded C, and a
    // self-signed certificate for it.
    EVP_PKEY *key = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    check(RSA_generate_key_ex(rsa, 2048, e, NULL) && EVP_PKEY_assign_RSA(key, rsa),
          "a 2048-bit RSA key wasn't generated");
    BN_free(e);
    X509 *cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                               (const uint8_t *)"reading_policy", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    X509_set_pubkey(cert, key);
    check(X509_sign(cert, key, EVP_sha256()), "the certificate wasn't signed");

    // PEM's legacy encryption, keyed by EVP_BytesToKey (U). A stream with
    // a certificate before and after the key reads as it always did.
    BIO *pem = BIO_new(BIO_s_mem());
    check(PEM_write_bio_X509(pem, cert) &&
              PEM_write_bio_PrivateKey_traditional(pem, key, EVP_aes_256_cbc(), NULL, 0, NULL,
                                                   "pw") &&
              PEM_write_bio_X509(pem, cert),
          "PEM with legacy encryption wasn't written");
    BIO *in = mem_of(pem);
    EVP_PKEY *read_key = PEM_read_bio_PrivateKey(in, NULL, NULL, "pw");
    X509 *after = PEM_read_bio_X509(in, NULL, NULL, NULL);
    check(read_key != NULL && after != NULL && X509_cmp(after, cert) == 0,
          "PEM with legacy encryption didn't read under the default policy");
    EVP_PKEY_free(read_key);
    X509_free(after);
    BIO_free(in);
    BIO *encrypted_cert = BIO_new(BIO_s_mem());
    check(PEM_ASN1_write_bio((i2d_of_void *)i2d_X509, PEM_STRING_X509, encrypted_cert, cert,
                             EVP_aes_256_cbc(), NULL, 0, NULL, "pw"),
          "a legacy-encrypted certificate wasn't written");

    peios_policy_testing_reject_below(GRADE_D);
    in = mem_of(pem);
    read_key = PEM_read_bio_PrivateKey(in, NULL, NULL, "pw");
    check(read_key == NULL && refused_last(),
          "PEM_read_bio_PrivateKey read a legacy-encrypted key policy refuses");
    after = PEM_read_bio_X509(in, NULL, NULL, NULL);
    check(after != NULL && X509_cmp(after, cert) == 0,
          "a refused PEM read lost its place in the caller's BIO");
    X509_free(after);
    BIO_free(in);
    in = mem_of(encrypted_cert);
    after = PEM_read_bio_X509(in, NULL, NULL, "pw");
    check(after == NULL && refused_last(),
          "PEM_read_bio_X509 read a legacy-encrypted certificate policy refuses");
    BIO_free(in);
    in = mem_of(encrypted_cert);
    STACK_OF(X509_INFO) *infos = PEM_X509_INFO_read_bio(in, NULL, NULL, "pw");
    check(infos == NULL && refused(),
          "PEM_X509_INFO_read_bio read a legacy-encrypted certificate policy refuses");
    BIO_free(in);
    peios_policy_testing_reject_below(GRADE_U);
    in = mem_of(encrypted_cert);
    infos = PEM_X509_INFO_read_bio(in, NULL, NULL, "pw");
    check(infos != NULL && sk_X509_INFO_num(infos) == 1,
          "PEM_X509_INFO_read_bio didn't read a legacy-encrypted certificate");
    sk_X509_INFO_pop_free(infos, X509_INFO_free);
    BIO_free(in);
    BIO_free(encrypted_cert);
    BIO_free(pem);

    // Encrypted private keys: PBES2 with AES-256-CBC and PBKDF2 over
    // HMAC-SHA1 (C), and PKCS #12's own PBE with Triple DES (U).
    PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(key);
    X509_SIG *pbes2 = PKCS8_encrypt(-1, EVP_aes_256_cbc(), "pw", 2, NULL, 0, 2048, p8inf);
    X509_SIG *des3 =
        PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, "pw", 2, NULL, 0, 2048, p8inf);
    check(pbes2 != NULL && des3 != NULL, "encrypted private keys weren't made");
    BIO *des3_der = BIO_new(BIO_s_mem());
    BIO *des3_pem = BIO_new(BIO_s_mem());
    check(i2d_PKCS8_bio(des3_der, des3) &&
              PEM_write_bio_PKCS8PrivateKey_nid(des3_pem, key, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                                NULL, 0, NULL, "pw"),
          "Triple DES encrypted keys weren't written");

    peios_policy_testing_reject_below(GRADE_D);
    PKCS8_PRIV_KEY_INFO *decrypted = PKCS8_decrypt(pbes2, "pw", 2);
    check(decrypted != NULL, "PKCS8_decrypt refused PBES2 with AES-256-CBC");
    PKCS8_PRIV_KEY_INFO_free(decrypted);
    decrypted = PKCS8_decrypt(des3, "pw", 2);
    check(decrypted == NULL && refused(), "PKCS8_decrypt decrypted a key policy refuses");
    uint8_t *der = NULL;
    int der_len = i2d_X509_SIG(des3, &der);
    CBS cbs;
    CBS_init(&cbs, der, (size_t)der_len);
    EVP_PKEY *parsed = PKCS8_parse_encrypted_private_key(&cbs, "pw", 2);
    check(parsed == NULL && refused(),
          "PKCS8_parse_encrypted_private_key decrypted a key policy refuses");
    OPENSSL_free(der);
    in = mem_of(des3_der);
    parsed = d2i_PKCS8PrivateKey_bio(in, NULL, NULL, "pw");
    check(parsed == NULL && refused(), "d2i_PKCS8PrivateKey_bio decrypted a key policy refuses");
    BIO_free(in);
    in = mem_of(des3_pem);
    parsed = PEM_read_bio_PrivateKey(in, NULL, NULL, "pw");
    check(parsed == NULL && refused(),
          "PEM_read_bio_PrivateKey decrypted an encrypted PKCS #8 key policy refuses");
    BIO_free(in);
    peios_policy_testing_reject_below(GRADE_U);
    in = mem_of(des3_pem);
    parsed = PEM_read_bio_PrivateKey(in, NULL, NULL, "pw");
    check(parsed != NULL, "PEM_read_bio_PrivateKey didn't read an encrypted PKCS #8 key");
    EVP_PKEY_free(parsed);
    BIO_free(in);
    BIO_free(des3_der);
    BIO_free(des3_pem);
    X509_SIG_free(pbes2);
    X509_SIG_free(des3);
    PKCS8_PRIV_KEY_INFO_free(p8inf);

    // PKCS #12, with an HMAC-SHA1 MAC (C): one with nothing encrypted, one
    // whose key is encrypted with Triple DES (U), and one whose
    // certificates are.
    PKCS12 *plain = PKCS12_create("pw", "name", key, cert, NULL, -1, -1, 0, 0, 0);
    PKCS12 *des3_key = PKCS12_create("pw", "name", key, cert, NULL, 0, -1, 0, 0, 0);
    PKCS12 *des3_certs = PKCS12_create("pw", "name", key, cert, NULL, -1,
                                       NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 0, 0, 0);
    check(plain != NULL && des3_key != NULL && des3_certs != NULL, "PKCS #12 files weren't made");
    EVP_PKEY *p12_key = NULL;
    X509 *p12_cert = NULL;

    peios_policy_testing_reject_below(GRADE_D);
    check(PKCS12_parse(plain, "pw", &p12_key, &p12_cert, NULL) && PKCS12_verify_mac(plain, "pw", 2),
          "PKCS12_parse refused a file with an HMAC-SHA1 MAC");
    EVP_PKEY_free(p12_key);
    X509_free(p12_cert);
    p12_key = NULL;
    p12_cert = NULL;
    check(!PKCS12_parse(des3_key, "pw", &p12_key, &p12_cert, NULL) && refused(),
          "PKCS12_parse decrypted a key policy refuses");
    check(!PKCS12_parse(des3_certs, "pw", &p12_key, &p12_cert, NULL) && refused(),
          "PKCS12_parse decrypted certificates policy refuses");
    // PKCS12_verify_mac clears the error queue when it fails, as when the
    // password is wrong.
    peios_policy_testing_reject_below(GRADE_B);
    check(!PKCS12_verify_mac(plain, "pw", 2), "PKCS12_verify_mac checked a MAC policy refuses");
    check(!PKCS12_parse(plain, "pw", &p12_key, &p12_cert, NULL) && refused(),
          "PKCS12_parse checked a MAC policy refuses");
    peios_policy_testing_reject_below(GRADE_U);
    PKCS12_free(plain);
    PKCS12_free(des3_key);
    PKCS12_free(des3_certs);

    // PKCS #7 envelopes: AES-256-CBC content, with the content key
    // transported by RSA's PKCS #1 v1.5 encryption (U).
    STACK_OF(X509) *recipients = sk_X509_new_null();
    sk_X509_push(recipients, cert);
    BIO *content = BIO_new_mem_buf("secret", 6);
    PKCS7 *envelope = PKCS7_encrypt(recipients, content, EVP_aes_256_cbc(), 0);
    BIO_free(content);
    BIO *out = BIO_new(BIO_s_mem());
    check(envelope != NULL && PKCS7_decrypt(envelope, key, cert, out, 0),
          "a PKCS #7 envelope wasn't made and decrypted under the default policy");
    BIO_free(out);
    PKCS7 *by_hand = PKCS7_new();
    check(PKCS7_set_type(by_hand, NID_pkcs7_enveloped) &&
              PKCS7_set_cipher(by_hand, EVP_des_ede3_cbc()) &&
              PKCS7_add_recipient(by_hand, cert) != NULL,
          "a Triple DES PKCS #7 envelope wasn't set up");

    peios_policy_testing_reject_below(GRADE_D);
    out = BIO_new(BIO_s_mem());
    check(!PKCS7_decrypt(envelope, key, cert, out, 0) && refused_last(),
          "PKCS7_decrypt decrypted an envelope policy refuses");
    BIO_free(out);
    BIO *encrypting = PKCS7_dataInit(by_hand, NULL);
    check(encrypting == NULL && refused_last(), "PKCS7_dataInit encrypted with a cipher policy refuses");
    BIO_free_all(encrypting);
    peios_policy_testing_reject_below(GRADE_U);
    PKCS7_free(by_hand);
    PKCS7_free(envelope);
    sk_X509_free(recipients);

    // Signatures by the RSA-2048 key (C): a PKCS #7 signature, an OCSP
    // response's, and the certificate's own.
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, cert);
    content = BIO_new_mem_buf("signed", 6);
    PKCS7 *signed_data = PKCS7_sign(cert, key, NULL, content, 0);
    BIO_free(content);
    check(signed_data != NULL, "PKCS7_sign didn't sign");
    // A response for the certificate itself, as its own issuer.
    OCSP_BASICRESP *response = OCSP_BASICRESP_new();
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, cert, cert);
    ASN1_TIME *now = X509_gmtime_adj(NULL, 0);
    STACK_OF(X509) *signers = sk_X509_new_null();
    sk_X509_push(signers, cert);
    check(OCSP_basic_add1_status(response, id, V_OCSP_CERTSTATUS_GOOD, 0, NULL, now, NULL) &&
              OCSP_basic_sign(response, cert, key, EVP_sha256(), NULL, 0),
          "OCSP_basic_sign didn't sign");
    OCSP_CERTID_free(id);
    ASN1_TIME_free(now);

    peios_policy_testing_reject_below(GRADE_C);
    out = BIO_new(BIO_s_mem());
    check(PKCS7_verify(signed_data, NULL, store, NULL, out, 0),
          "PKCS7_verify refused an RSA-2048 signature at C");
    BIO_free(out);
    check(OCSP_basic_verify(response, signers, store, 0) == 1,
          "OCSP_basic_verify refused an RSA-2048 signature at C");
    check(X509_verify(cert, key) == 1, "X509_verify refused an RSA-2048 signature at C");

    peios_policy_testing_reject_below(GRADE_B);
    out = BIO_new(BIO_s_mem());
    check(!PKCS7_verify(signed_data, NULL, store, NULL, out, 0) && refused(),
          "PKCS7_verify verified a signature policy refuses");
    BIO_free(out);
    check(OCSP_basic_verify(response, signers, store, 0) != 1 && refused(),
          "OCSP_basic_verify verified a signature policy refuses");
    check(X509_verify(cert, key) != 1 && refused(),
          "X509_verify verified a signature policy refuses");
    peios_policy_testing_reject_below(GRADE_U);
    PKCS7_free(signed_data);
    OCSP_BASICRESP_free(response);
    sk_X509_free(signers);
    X509_STORE_free(store);

    X509_free(cert);
    EVP_PKEY_free(key);
    if (failures == 0) {
        puts("reading_policy: ok");
    }
    return failures != 0;
}
