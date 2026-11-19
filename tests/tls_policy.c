// libpssl's TLS policy, through a handshake between two of its own
// connections in memory: one with a P-256 certificate completes and carries
// data; one whose server has a 512-bit RSA key, on the floor, fails with
// Peios's error, and the connection stays failed.

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define REFUSED_BY_POLICY 1000

// A 512-bit RSA key and a self-signed certificate for it, made for this test
// alone with OpenSSL: Peios's libraries won't make one. Deliberately weak,
// and secret to nothing.
static const char kRSA512Key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAtxHqD8Ny5JEATS8Z\n"
    "C2+/bEoca6tOzNGNmFt0HY+dERo/UMy8OnIvG5oR6KubaZvS9ZmlOq0dKQ859mxe\n"
    "cZifDwIDAQABAkAl9Nzmr8tegIHjfuRebqjttt/1ousPpFMLR8rnZiNWrBSiArhD\n"
    "M+KS6fm29g08bLMwOyy+jotZujaFjeBjJUghAiEA4gLDJg3J5d4s9YuiaBDdIHLT\n"
    "CeZrn2yM6vSd81XAnhMCIQDPXITVcO5p0X/dHkPT0W+mvK8AIQYle+VAnhjDQuyq\n"
    "lQIhAM3LjByrc4sO6ktPsTsnF+LDC205VggdlJcg1G5NSA3nAiEAzMBGSZuhTsuW\n"
    "vffMcbMz1CgrhK0XLJwR2qRBP00t86ECIFyt4VCMA10q0bDED0b9kTWsOofawGOe\n"
    "Y4236/QXZPEp\n"
    "-----END PRIVATE KEY-----\n"
    ;
static const char kRSA512Cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBezCCASWgAwIBAgIUGre9oRls1vzGk1hZoP+mM1oBBBkwDQYJKoZIhvcNAQEL\n"
    "BQAwETEPMA0GA1UEAwwGcnNhNTEyMCAXDTI2MTExOTIzNTMxMVoYDzIxMjYxMDI2\n"
    "MjM1MzExWjARMQ8wDQYDVQQDDAZyc2E1MTIwXDANBgkqhkiG9w0BAQEFAANLADBI\n"
    "AkEAtxHqD8Ny5JEATS8ZC2+/bEoca6tOzNGNmFt0HY+dERo/UMy8OnIvG5oR6Kub\n"
    "aZvS9ZmlOq0dKQ859mxecZifDwIDAQABo1MwUTAdBgNVHQ4EFgQUxsxriwUL68b/\n"
    "YuMQGKxpxA2fz+4wHwYDVR0jBBgwFoAUxsxriwUL68b/YuMQGKxpxA2fz+4wDwYD\n"
    "VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAGIvrfDoABi43iMpioVDhjy9\n"
    "juot/AjrLVG/PJ60a5ZODeZBZ/otYCGk1QoZi1GyMVtwaSOeMBCX3Ra6kc9wx90=\n"
    "-----END CERTIFICATE-----\n"
    ;

static int failures = 0;

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "tls_policy: %s\n", what);
        ERR_print_errors_fp(stderr);
        failures++;
    }
}

// Runs a handshake between `client` and `server` until both finish or one
// fails; returns whether both finished.
static int handshake(SSL *client, SSL *server) {
    for (int round = 0; round < 32; round++) {
        int c = SSL_do_handshake(client), s = SSL_do_handshake(server);
        if (c == 1 && s == 1) {
            return 1;
        }
        if ((c != 1 && SSL_get_error(client, c) != SSL_ERROR_WANT_READ) ||
            (s != 1 && SSL_get_error(server, s) != SSL_ERROR_WANT_READ)) {
            return 0;
        }
    }
    return 0;
}

// A client and server connected by a BIO pair, the server with `key` and
// `cert`, and neither above `max_version`.
static void connect_pair(EVP_PKEY *key, X509 *cert, uint16_t max_version, SSL **client,
                         SSL **server) {
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_max_proto_version(server_ctx, max_version);
    SSL_CTX_use_certificate(server_ctx, cert);
    SSL_CTX_use_PrivateKey(server_ctx, key);
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_max_proto_version(client_ctx, max_version);
    *server = SSL_new(server_ctx);
    *client = SSL_new(client_ctx);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    BIO *client_bio, *server_bio;
    BIO_new_bio_pair(&client_bio, 0, &server_bio, 0);
    SSL_set_bio(*client, client_bio, client_bio);
    SSL_set_bio(*server, server_bio, server_bio);
    SSL_set_connect_state(*client);
    SSL_set_accept_state(*server);
}

static X509 *p256_self_signed(EVP_PKEY **key_out) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec);
    EVP_PKEY *key = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(key, ec);
    X509 *cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                               (const uint8_t *)"tls_policy", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, EVP_sha256());
    *key_out = key;
    return cert;
}

int main(void) {
    EVP_PKEY *key;
    X509 *cert = p256_self_signed(&key);
    SSL *client, *server;
    connect_pair(key, cert, TLS1_3_VERSION, &client, &server);
    check(handshake(client, server), "a TLS handshake with a P-256 certificate failed");
    char buf[8] = {0};
    check(SSL_write(client, "ping", 4) == 4 && SSL_read(server, buf, sizeof(buf)) == 4 &&
              memcmp(buf, "ping", 4) == 0,
          "data didn't cross the connection");
    SSL_free(client);
    SSL_free(server);
    X509_free(cert);
    EVP_PKEY_free(key);

    BIO *bio = BIO_new_mem_buf(kRSA512Key, -1);
    EVP_PKEY *weak_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    bio = BIO_new_mem_buf(kRSA512Cert, -1);
    X509 *weak_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    check(weak_key != NULL && weak_cert != NULL, "the 512-bit RSA key and certificate didn't load");
    if (weak_key != NULL && weak_cert != NULL) {
        // TLS 1.2: TLS 1.3 signs with RSA-PSS, which a 512-bit key is too
        // small for, so AWS-LC itself would refuse it first.
        connect_pair(weak_key, weak_cert, TLS1_2_VERSION, &client, &server);
        ERR_clear_error();
        check(!handshake(client, server), "a TLS handshake with a 512-bit RSA key completed");
        int refused = 0;
        uint32_t error;
        while ((error = ERR_get_error()) != 0) {
            refused |= ERR_GET_LIB(error) == ERR_LIB_USER && ERR_GET_REASON(error) == REFUSED_BY_POLICY;
        }
        check(refused, "the 512-bit RSA handshake didn't fail with Peios's error");
        check(SSL_write(client, "ping", 4) <= 0 && SSL_write(server, "ping", 4) <= 0,
              "a refused connection carried data");
        ERR_clear_error();
        SSL_free(client);
        SSL_free(server);
    }
    X509_free(weak_cert);
    EVP_PKEY_free(weak_key);

    if (failures == 0) {
        puts("tls_policy: ok");
    }
    return failures != 0;
}
