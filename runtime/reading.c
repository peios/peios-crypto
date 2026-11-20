/* The policy runtime's checks on data that names its own algorithm:
   password-encrypted private keys, PKCS #12 files, PEM's legacy
   encryption and PKCS #7 envelopes.

   AWS-LC decrypts these inside its own calls, from one source file to
   another, so libpcrypto is linked to wrap the functions where it does:
   bindings.toml's internal hooks call the checks here, and its internal
   entries are this file's wraps, of functions outside AWS-LC's API.
   Compiled against AWS-LC's prefixed headers, so it calls AWS-LC
   directly, and its internal headers, so that a changed declaration fails
   the build.

   Each parse follows AWS-LC's own. Data AWS-LC would refuse to parse, or
   an algorithm it doesn't support, is let through for AWS-LC to report. */
#include <pthread.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "crypto/pkcs7/internal.h"
#include "crypto/pkcs8/internal.h"

#include "peios_policy.h"
#include "peios_prefix.h"
#include "policy_ids.h"

/* PBES2's encryption schemes, as p5_pbev2.c's kCipherOIDs lists them. */
static const EVP_CIPHER *pbes2_cipher(int nid) {
    switch (nid) {
        case NID_rc2_cbc:
            return EVP_rc2_cbc();
        case NID_des_ede3_cbc:
            return EVP_des_ede3_cbc();
        case NID_aes_128_cbc:
            return EVP_aes_128_cbc();
        case NID_aes_192_cbc:
            return EVP_aes_192_cbc();
        case NID_aes_256_cbc:
            return EVP_aes_256_cbc();
        default:
            return NULL;
    }
}

/* PBES2's parameters, RFC 8018 appendix A.4, as PKCS5_pbe2_decrypt_init
   reads them: PBKDF2, with its PRF, and the cipher. */
static int pbes2(CBS *param) {
    CBS pbe, kdf, kdf_obj, enc, enc_obj, pbkdf2, salt;
    uint64_t iterations;
    if (!CBS_get_asn1(param, &pbe, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&pbe, &kdf, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&pbe, &enc, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&kdf, &kdf_obj, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&enc, &enc_obj, CBS_ASN1_OBJECT) ||
        OBJ_cbs2nid(&kdf_obj) != NID_id_pbkdf2) {
        return 1;
    }
    const EVP_CIPHER *cipher = pbes2_cipher(OBJ_cbs2nid(&enc_obj));
    if (cipher == NULL ||
        !CBS_get_asn1(&kdf, &pbkdf2, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&pbkdf2, &salt, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1_uint64(&pbkdf2, &iterations) ||
        (CBS_peek_asn1_tag(&pbkdf2, CBS_ASN1_INTEGER) &&
         !CBS_get_asn1(&pbkdf2, NULL, CBS_ASN1_INTEGER))) {
        return 1;
    }
    /* hmacWithSHA1 is the default PRF. */
    const EVP_MD *md = EVP_sha1();
    if (CBS_len(&pbkdf2) != 0) {
        CBS prf_alg, prf;
        if (!CBS_get_asn1(&pbkdf2, &prf_alg, CBS_ASN1_SEQUENCE) ||
            !CBS_get_asn1(&prf_alg, &prf, CBS_ASN1_OBJECT)) {
            return 1;
        }
        int prf_nid = OBJ_cbs2nid(&prf);
        if (prf_nid == NID_hmacWithSHA256) {
            md = EVP_sha256();
        } else if (prf_nid != NID_hmacWithSHA1) {
            return 1;
        }
    }
    return peios_policy_cipher(cipher, PEIOS_OP_DECRYPT) &&
           peios_policy_algorithm(PEIOS_ENTRY_pbkdf2_kdf) && peios_policy_digest(md, PEIOS_OP_HMAC);
}

/* Whether data may be decrypted with the password-based encryption scheme
   `algorithm` names: an AlgorithmIdentifier's contents, as
   pkcs8_pbe_decrypt reads them. AWS-LC decrypts with the schemes
   pkcs8.c's kBuiltinPBE lists, and refuses any other itself. */
static int pbe(const CBS *algorithm) {
    CBS alg = *algorithm, obj;
    if (!CBS_get_asn1(&alg, &obj, CBS_ASN1_OBJECT)) {
        return 1;
    }
    switch (OBJ_cbs2nid(&obj)) {
        case NID_pbe_WithSHA1And40BitRC2_CBC:
            return peios_policy_algorithm(PEIOS_ENTRY_pkcs12_pbe_sha1_rc2_40_decrypt);
        case NID_pbe_WithSHA1And128BitRC4:
            return peios_policy_algorithm(PEIOS_ENTRY_pkcs12_pbe_sha1_rc4_128_decrypt);
        case NID_pbe_WithSHA1And3_Key_TripleDES_CBC:
            return peios_policy_algorithm(PEIOS_ENTRY_pkcs12_pbe_sha1_3des_decrypt);
        case NID_pbes2:
            return pbes2(&alg);
        default:
            return 1;
    }
}

int peios_policy_encrypted_private_key(const CBS *cbs) {
    if (cbs == NULL) {
        return 1;
    }
    /* EncryptedPrivateKeyInfo, RFC 5208 section 6. */
    CBS in = *cbs, epki, algorithm;
    if (!CBS_get_asn1(&in, &epki, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&epki, &algorithm, CBS_ASN1_SEQUENCE)) {
        return 1;
    }
    return pbe(&algorithm);
}

/* pkcs8_pbe_decrypt, which PKCS #12's encrypted contents are decrypted
   by. Its call from PKCS8_parse_encrypted_private_key, in its own file,
   isn't wrapped: that function's hook checks the same. */
extern __typeof__(pkcs8_pbe_decrypt) PEIOS_INNER(pkcs8_pbe_decrypt);
__typeof__(pkcs8_pbe_decrypt) PEIOS_WRAP(pkcs8_pbe_decrypt);

int PEIOS_WRAP(pkcs8_pbe_decrypt)(uint8_t **out, size_t *out_len, CBS *algorithm,
                                  const char *pass, size_t pass_len, const uint8_t *in,
                                  size_t in_len) {
    if (algorithm != NULL && !pbe(algorithm)) {
        return 0;
    }
    return PEIOS_INNER(pkcs8_pbe_decrypt)(out, out_len, algorithm, pass, pass_len, in, in_len);
}

/* pkcs12_key_gen, which keys a PKCS #12 file's MAC, as it's checked and
   as it's made, with the digest the file names. Its other uses, keying
   PKCS #12's own encryption, are checked as their scheme is. */
extern __typeof__(pkcs12_key_gen) PEIOS_INNER(pkcs12_key_gen);
__typeof__(pkcs12_key_gen) PEIOS_WRAP(pkcs12_key_gen);

int PEIOS_WRAP(pkcs12_key_gen)(const char *pass, size_t pass_len, const uint8_t *salt,
                               size_t salt_len, uint8_t id, uint32_t iterations, size_t out_len,
                               uint8_t *out, const EVP_MD *md) {
    if (id == PKCS12_MAC_ID && md != NULL && !peios_policy_digest(md, PEIOS_OP_HMAC)) {
        return 0;
    }
    return PEIOS_INNER(pkcs12_key_gen)(pass, pass_len, salt, salt_len, id, iterations, out_len,
                                       out, md);
}

int peios_policy_pem_cipher(const EVP_CIPHER_INFO *cipher) {
    if (cipher == NULL || cipher->cipher == NULL) {
        return 1;
    }
    /* PEM_do_header keys the cipher with EVP_BytesToKey, over MD5. */
    return peios_policy_cipher(cipher->cipher, PEIOS_OP_DECRYPT) &&
           peios_policy_algorithm(PEIOS_ENTRY_evp_bytestokey_kdf);
}

/* A PEM read in progress: the block read so far, which a password
   callback checks the encryption of, and the caller's callback. */
struct pem_read {
    BUF_MEM *block;
    int lost;
    pem_password_cb *cb;
    void *u;
    int refused;
};

/* A filter in front of the caller's BIO that records each PEM block as
   PEM_read_bio reads it, a line at a time. */
static int recorder_gets(BIO *bio, char *buf, int size) {
    struct pem_read *read = BIO_get_data(bio);
    int n = BIO_gets(BIO_next(bio), buf, size);
    BIO_copy_next_retry(bio);
    if (n > 0) {
        if (strncmp(buf, "-----BEGIN ", 11) == 0) {
            read->block->length = 0;
        }
        read->lost |= !BUF_MEM_append(read->block, buf, (size_t)n);
    }
    return n;
}

static int recorder_read(BIO *bio, char *buf, int size) {
    struct pem_read *read = BIO_get_data(bio);
    int n = BIO_read(BIO_next(bio), buf, size);
    BIO_copy_next_retry(bio);
    if (n > 0) {
        read->lost |= !BUF_MEM_append(read->block, buf, (size_t)n);
    }
    return n;
}

static long recorder_ctrl(BIO *bio, int cmd, long larg, void *parg) {
    return BIO_ctrl(BIO_next(bio), cmd, larg, parg);
}

static BIO_METHOD *recorder_method;
static pthread_once_t recorder_once = PTHREAD_ONCE_INIT;

static void make_recorder(void) {
    BIO_METHOD *method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "Peios PEM recorder");
    if (method != NULL && BIO_meth_set_gets(method, recorder_gets) &&
        BIO_meth_set_read(method, recorder_read) && BIO_meth_set_ctrl(method, recorder_ctrl)) {
        recorder_method = method;
    } else {
        BIO_meth_free(method);
    }
}

/* Whether the block a PEM read has just read may be decrypted: its
   header, read as PEM_read_bio reads it, names the cipher. A block that
   can't be read back is refused as ungraded, as nothing could check it. */
static int block_allowed(const struct pem_read *read) {
    if (read->lost) {
        return peios_policy_algorithm(NULL);
    }
    BIO *mem = BIO_new_mem_buf(read->block->data, (ossl_ssize_t)read->block->length);
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len;
    EVP_CIPHER_INFO cipher;
    int ok;
    if (mem != NULL && PEM_read_bio(mem, &name, &header, &data, &len) &&
        PEM_get_EVP_CIPHER_INFO(header, &cipher)) {
        ok = peios_policy_pem_cipher(&cipher);
    } else {
        ok = peios_policy_algorithm(NULL);
    }
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    BIO_free(mem);
    return ok;
}

/* The password callback PEM_do_header asks just before it decrypts, once
   the block's been read: it checks the block's encryption, then asks the
   caller's callback, or AWS-LC's default, for the password. A refusal
   marks Peios's error, so that the read can drop what AWS-LC adds. */
static int password(char *buf, int size, int rwflag, void *arg) {
    struct pem_read *read = arg;
    if (!block_allowed(read)) {
        read->refused = ERR_GET_REASON(ERR_peek_last_error());
        ERR_set_mark();
        return -1;
    }
    if (read->cb != NULL) {
        return read->cb(buf, size, rwflag, read->u);
    }
    return PEM_def_callback(buf, size, rwflag, read->u);
}

extern __typeof__(PEM_bytes_read_bio) PEIOS_INNER(PEM_bytes_read_bio);

int peios_policy_pem_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                                    const char *name, BIO *bp, pem_password_cb *cb, void *u) {
    pthread_once(&recorder_once, make_recorder);
    struct pem_read read = {.block = BUF_MEM_new(), .cb = cb, .u = u};
    BIO *recorder = recorder_method != NULL && bp != NULL ? BIO_new(recorder_method) : NULL;
    if (read.block == NULL || recorder == NULL) {
        /* Nothing to read with, or nothing to read: AWS-LC reports it. */
        BUF_MEM_free(read.block);
        BIO_free(recorder);
        if (bp == NULL) {
            return PEIOS_INNER(PEM_bytes_read_bio)(pdata, plen, pnm, name, bp, cb, u);
        }
        OPENSSL_PUT_ERROR(PEM, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    BIO_set_data(recorder, &read);
    BIO_set_init(recorder, 1);
    BIO_push(recorder, bp);
    int ret = PEIOS_INNER(PEM_bytes_read_bio)(pdata, plen, pnm, name, recorder, password, &read);
    /* The caller's BIO is still the caller's: unlink it before freeing the
       filter, which would free the chain. */
    BIO_pop(recorder);
    BIO_free(recorder);
    BUF_MEM_free(read.block);
    if (read.refused) {
        ERR_pop_to_mark();
        return 0;
    }
    return ret;
}

/* Recipients' key transport, decrypting the content key as PKCS #7's
   recipient decryption does: with the private key, and RSA's PKCS #1
   v1.5 padding. */
static int key_transport_decrypt(const EVP_PKEY *pkey) {
    if (!peios_policy_pkey(pkey, PEIOS_OP_DECRYPT)) {
        return 0;
    }
    int id = EVP_PKEY_id(pkey);
    if (id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS) {
        return peios_policy_rsa_padding(RSA_PKCS1_PADDING, PEIOS_OP_DECRYPT);
    }
    return 1;
}

int peios_policy_pkcs7_decrypt(const PKCS7 *p7, const EVP_PKEY *pkey) {
    if (p7 == NULL || pkey == NULL || p7->d.ptr == NULL ||
        OBJ_obj2nid(p7->type) != NID_pkcs7_enveloped || p7->d.enveloped->enc_data == NULL) {
        return 1;
    }
    /* The content's cipher, as pkcs7_data_decode finds it. */
    const X509_ALGOR *alg = p7->d.enveloped->enc_data->algorithm;
    const ASN1_OBJECT *obj = NULL;
    if (alg != NULL) {
        X509_ALGOR_get0(&obj, NULL, NULL, alg);
    }
    const EVP_CIPHER *cipher = obj != NULL ? EVP_get_cipherbynid(OBJ_obj2nid(obj)) : NULL;
    if (cipher == NULL) {
        return 1;
    }
    return peios_policy_cipher(cipher, PEIOS_OP_DECRYPT) && key_transport_decrypt(pkey);
}

int peios_policy_pkcs7_data_init(const PKCS7 *p7) {
    if (p7 == NULL || p7->d.ptr == NULL) {
        return 1;
    }
    /* Its digests are checked as PKCS7_dataInit sets each up, and its
       signatures as PKCS7_dataFinal makes them. */
    const PKCS7_ENC_CONTENT *enc;
    const STACK_OF(PKCS7_RECIP_INFO) *recipients;
    switch (OBJ_obj2nid(p7->type)) {
        case NID_pkcs7_signedAndEnveloped:
            enc = p7->d.signed_and_enveloped->enc_data;
            recipients = p7->d.signed_and_enveloped->recipientinfo;
            break;
        case NID_pkcs7_enveloped:
            enc = p7->d.enveloped->enc_data;
            recipients = p7->d.enveloped->recipientinfo;
            break;
        default:
            return 1;
    }
    if (enc != NULL && !peios_policy_cipher(enc->cipher, PEIOS_OP_ENCRYPT)) {
        return 0;
    }
    for (size_t i = 0; i < sk_PKCS7_RECIP_INFO_num(recipients); i++) {
        const PKCS7_RECIP_INFO *ri = sk_PKCS7_RECIP_INFO_value(recipients, i);
        if (ri->cert != NULL && !peios_policy_key_transport(X509_get0_pubkey(ri->cert))) {
            return 0;
        }
    }
    return 1;
}
