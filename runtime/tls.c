/* Peios crypto policy for TLS, in libpssl. Configuration has many ways to
   choose a connection's algorithms, so rather than check each, the calls
   that can run or finish a handshake check what it negotiated once it's
   finished: the protocol version, the cipher suite, the key-exchange
   group, the keys that signed and the signature algorithms they used, the
   peer's verified certificate chain, and any SRTP profile. A connection
   policy refuses is failed with an insufficient_security alert, and every
   later call on it fails too.

   Built against AWS-LC's unprefixed headers, as the hooks are, so that its
   calls into libcrypto go through libpcrypto's exports; it reaches
   libssl's own handshake functions by their prefixed names. */
#include <pthread.h>
#include <stdint.h>

#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "peios_policy.h"
#include "peios_prefix.h"

extern __typeof__(SSL_do_handshake) PEIOS_REAL(SSL_do_handshake);
extern __typeof__(SSL_connect) PEIOS_REAL(SSL_connect);
extern __typeof__(SSL_accept) PEIOS_REAL(SSL_accept);
extern __typeof__(SSL_read) PEIOS_REAL(SSL_read);
extern __typeof__(SSL_read_ex) PEIOS_REAL(SSL_read_ex);
extern __typeof__(SSL_peek) PEIOS_REAL(SSL_peek);
extern __typeof__(SSL_peek_ex) PEIOS_REAL(SSL_peek_ex);
extern __typeof__(SSL_write) PEIOS_REAL(SSL_write);
extern __typeof__(SSL_write_ex) PEIOS_REAL(SSL_write_ex);

/* Where a connection keeps its state: the number of the handshake checked
   last, shifted left, and whether policy refused it, in the low bit. */
static int ex_index = -1;
static pthread_once_t ex_once = PTHREAD_ONCE_INIT;

static void make_ex_index(void) {
    ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

static int version_ok(const SSL *ssl) {
    switch (SSL_version(ssl)) {
        case TLS1_VERSION:
            return peios_policy_name("tls10", PEIOS_OP_NEGOTIATE);
        case TLS1_1_VERSION:
            return peios_policy_name("tls11", PEIOS_OP_NEGOTIATE);
        case TLS1_2_VERSION:
            return peios_policy_name("tls12", PEIOS_OP_NEGOTIATE);
        case TLS1_3_VERSION:
            return peios_policy_name("tls13", PEIOS_OP_NEGOTIATE);
        case DTLS1_VERSION:
            return peios_policy_name("dtls10", PEIOS_OP_NEGOTIATE);
        case DTLS1_2_VERSION:
            return peios_policy_name("dtls12", PEIOS_OP_NEGOTIATE);
        default:
            return peios_policy_algorithm(NULL);
    }
}

/* A cipher suite: its cipher, its record MAC if it has one, and its key
   exchange where the suite fixes it. Its cipher is checked for
   encrypting, the stricter of the two directions. */
static int suite_ok(const SSL_CIPHER *suite) {
    if (suite == NULL) {
        return 1;
    }
    if (SSL_CIPHER_get_cipher_nid(suite) == NID_undef) {
        /* A NULL-cipher suite, TLS_RSA_WITH_NULL_SHA say. */
        return peios_policy_name("tls-null-cipher", PEIOS_OP_NEGOTIATE);
    }
    const EVP_CIPHER *cipher = EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(suite));
    if (cipher == NULL) {
        return peios_policy_algorithm(NULL);
    }
    if (!peios_policy_cipher(cipher, PEIOS_OP_ENCRYPT)) {
        return 0;
    }
    int mac_nid = SSL_CIPHER_get_digest_nid(suite);
    if (mac_nid != NID_undef) {
        const EVP_MD *mac = EVP_get_digestbynid(mac_nid);
        if (mac == NULL || !peios_policy_digest(mac, PEIOS_OP_HMAC)) {
            return mac == NULL ? peios_policy_algorithm(NULL) : 0;
        }
    }
    switch (SSL_CIPHER_get_kx_nid(suite)) {
        case NID_kx_rsa:
            /* RSA key transport: the client encrypts the premaster secret
               with PKCS #1 v1.5. */
            return peios_policy_rsa_padding(RSA_PKCS1_PADDING, PEIOS_OP_ENCRYPT);
        case NID_kx_psk:
            return peios_policy_name("tls-psk", PEIOS_OP_NEGOTIATE);
        default:
            return 1;
    }
}

/* The key-exchange group: a curve, ML-KEM, or a hybrid of the two, both of
   whose parts are checked. None (0) is a suite without one, RSA key
   transport or a PSK alone, which the suite's check covers. */
static int group_ok(const SSL *ssl) {
    switch (SSL_get_group_id(ssl)) {
        case 0:
            return 1;
        case SSL_GROUP_SECP224R1:
            return peios_policy_name("ec-p224", PEIOS_OP_DERIVE);
        case SSL_GROUP_SECP256R1:
            return peios_policy_name("ec-p256", PEIOS_OP_DERIVE);
        case SSL_GROUP_SECP384R1:
            return peios_policy_name("ec-p384", PEIOS_OP_DERIVE);
        case SSL_GROUP_SECP521R1:
            return peios_policy_name("ec-p521", PEIOS_OP_DERIVE);
        case SSL_GROUP_X25519:
            return peios_policy_name("x25519", PEIOS_OP_DERIVE);
        case SSL_GROUP_SECP256R1_MLKEM768:
            return peios_policy_name("ec-p256", PEIOS_OP_DERIVE) &&
                   peios_policy_name("ml-kem-768", PEIOS_OP_ENCAPSULATE);
        case SSL_GROUP_X25519_MLKEM768:
            return peios_policy_name("x25519", PEIOS_OP_DERIVE) &&
                   peios_policy_name("ml-kem-768", PEIOS_OP_ENCAPSULATE);
        case SSL_GROUP_SECP384R1_MLKEM1024:
            return peios_policy_name("ec-p384", PEIOS_OP_DERIVE) &&
                   peios_policy_name("ml-kem-1024", PEIOS_OP_ENCAPSULATE);
        case SSL_GROUP_MLKEM512:
            return peios_policy_name("ml-kem-512", PEIOS_OP_ENCAPSULATE);
        case SSL_GROUP_MLKEM768:
            return peios_policy_name("ml-kem-768", PEIOS_OP_ENCAPSULATE);
        case SSL_GROUP_MLKEM1024:
            return peios_policy_name("ml-kem-1024", PEIOS_OP_ENCAPSULATE);
        default:
            return peios_policy_algorithm(NULL);
    }
}

/* The peer's key, with the signature algorithm it signed with if it
   signed; our own key, which signs; and the peer's verified chain. */
static int keys_ok(const SSL *ssl) {
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer != NULL) {
        EVP_PKEY *key = X509_get0_pubkey(peer);
        uint16_t sigalg = SSL_get_peer_signature_algorithm(ssl);
        int ok = sigalg != 0
                     ? peios_policy_pkey_md(key, SSL_get_signature_algorithm_digest(sigalg),
                                            PEIOS_OP_VERIFY)
                     : peios_policy_pkey(key, PEIOS_OP_VERIFY);
        X509_free(peer);
        if (!ok) {
            return 0;
        }
    }
    EVP_PKEY *own = SSL_get_privatekey(ssl);
    if (own != NULL && !peios_policy_pkey(own, PEIOS_OP_SIGN)) {
        return 0;
    }
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    return chain == NULL || peios_policy_chain(chain);
}

static int srtp_ok(const SSL *ssl) {
    const SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile((SSL *)ssl);
    if (profile == NULL) {
        return 1;
    }
    switch (profile->id) {
        case SRTP_AES128_CM_SHA1_80:
            return peios_policy_name("srtp-aes128-cm-sha1-80", PEIOS_OP_NEGOTIATE);
        case SRTP_AES128_CM_SHA1_32:
            return peios_policy_name("srtp-aes128-cm-sha1-32", PEIOS_OP_NEGOTIATE);
        case SRTP_AEAD_AES_128_GCM:
            return peios_policy_name("srtp-aead-aes-128-gcm", PEIOS_OP_NEGOTIATE);
        case SRTP_AEAD_AES_256_GCM:
            return peios_policy_name("srtp-aead-aes-256-gcm", PEIOS_OP_NEGOTIATE);
        case SRTP_NULL_SHA1_80:
        case SRTP_NULL_SHA1_32:
            return peios_policy_name("srtp-null", PEIOS_OP_NEGOTIATE);
        default:
            return peios_policy_algorithm(NULL);
    }
}

static int negotiated_ok(const SSL *ssl) {
    return version_ok(ssl) && suite_ok(SSL_get_current_cipher(ssl)) && group_ok(ssl) &&
           keys_ok(ssl) && srtp_ok(ssl);
}

/* Whether `ssl` may carry on: checks a handshake once it's finished, once,
   and remembers what policy decided. A connection that can't keep its
   state is checked every time. */
static int allowed(SSL *ssl) {
    pthread_once(&ex_once, make_ex_index);
    uintptr_t state = ex_index >= 0 ? (uintptr_t)SSL_get_ex_data(ssl, ex_index) : 0;
    if (SSL_in_init(ssl) || !SSL_is_init_finished(ssl)) {
        return !(state & 1);
    }
    uintptr_t handshake = (uintptr_t)SSL_total_renegotiations(ssl) + 1;
    if (ex_index >= 0 && state >> 1 == handshake) {
        if (state & 1) {
            peios_policy_refused();
        }
        return !(state & 1);
    }
    int ok = negotiated_ok(ssl);
    if (ex_index >= 0) {
        SSL_set_ex_data(ssl, ex_index, (void *)(handshake << 1 | (uintptr_t)!ok));
    }
    if (!ok) {
        SSL_send_fatal_alert(ssl, SSL_AD_INSUFFICIENT_SECURITY);
    }
    return ok;
}

/* Whether a connection policy has already refused, which a call mustn't
   carry on, reporting it again if so. */
static int refused_before(SSL *ssl) {
    pthread_once(&ex_once, make_ex_index);
    if (ex_index < 0 || ssl == NULL || !((uintptr_t)SSL_get_ex_data(ssl, ex_index) & 1)) {
        return 0;
    }
    peios_policy_refused();
    return 1;
}

int peios_tls_do_handshake(SSL *ssl) {
    if (refused_before(ssl)) {
        return -1;
    }
    int ret = PEIOS_REAL(SSL_do_handshake)(ssl);
    return ssl != NULL && !allowed(ssl) ? -1 : ret;
}

int peios_tls_connect(SSL *ssl) {
    if (refused_before(ssl)) {
        return -1;
    }
    int ret = PEIOS_REAL(SSL_connect)(ssl);
    return ssl != NULL && !allowed(ssl) ? -1 : ret;
}

int peios_tls_accept(SSL *ssl) {
    if (refused_before(ssl)) {
        return -1;
    }
    int ret = PEIOS_REAL(SSL_accept)(ssl);
    return ssl != NULL && !allowed(ssl) ? -1 : ret;
}

int peios_tls_read(SSL *ssl, void *buf, int num) {
    if (refused_before(ssl)) {
        return -1;
    }
    int ret = PEIOS_REAL(SSL_read)(ssl, buf, num);
    return ssl != NULL && !allowed(ssl) ? -1 : ret;
}

int peios_tls_read_ex(SSL *ssl, void *buf, size_t num, size_t *read_bytes) {
    if (refused_before(ssl)) {
        return 0;
    }
    int ret = PEIOS_REAL(SSL_read_ex)(ssl, buf, num, read_bytes);
    return ssl != NULL && !allowed(ssl) ? 0 : ret;
}

int peios_tls_peek(SSL *ssl, void *buf, int num) {
    if (refused_before(ssl)) {
        return -1;
    }
    int ret = PEIOS_REAL(SSL_peek)(ssl, buf, num);
    return ssl != NULL && !allowed(ssl) ? -1 : ret;
}

int peios_tls_peek_ex(SSL *ssl, void *buf, size_t num, size_t *read_bytes) {
    if (refused_before(ssl)) {
        return 0;
    }
    int ret = PEIOS_REAL(SSL_peek_ex)(ssl, buf, num, read_bytes);
    return ssl != NULL && !allowed(ssl) ? 0 : ret;
}

int peios_tls_write(SSL *ssl, const void *buf, int num) {
    if (refused_before(ssl)) {
        return -1;
    }
    int ret = PEIOS_REAL(SSL_write)(ssl, buf, num);
    return ssl != NULL && !allowed(ssl) ? -1 : ret;
}

int peios_tls_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) {
    if (refused_before(ssl)) {
        return 0;
    }
    int ret = PEIOS_REAL(SSL_write_ex)(ssl, buf, num, written);
    return ssl != NULL && !allowed(ssl) ? 0 : ret;
}
