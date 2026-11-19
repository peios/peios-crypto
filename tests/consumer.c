// A program built against libpcrypto's and libpssl's headers as any
// OpenSSL consumer is: it uses an ASN.1 item table by its address, which
// the wrappers export as data, a digest and a TLS context.

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

static int fail(const char *what) {
    fprintf(stderr, "consumer: %s\n", what);
    return 1;
}

int main(void) {
    static const unsigned char der[] = {0x04, 0x03, 'a', 'b', 'c'};
    const unsigned char *in = der;
    ASN1_OCTET_STRING *octets = (ASN1_OCTET_STRING *)ASN1_item_d2i(
        NULL, &in, sizeof(der), ASN1_ITEM_rptr(ASN1_OCTET_STRING));
    if (octets == NULL || ASN1_STRING_length(octets) != 3 ||
        memcmp(ASN1_STRING_get0_data(octets), "abc", 3) != 0) {
        return fail("ASN1_item_d2i didn't decode the OCTET STRING");
    }
    unsigned char *out = NULL;
    int out_len = ASN1_item_i2d((ASN1_VALUE *)octets, &out,
                                ASN1_ITEM_rptr(ASN1_OCTET_STRING));
    if (out_len != (int)sizeof(der) || memcmp(out, der, sizeof(der)) != 0) {
        return fail("ASN1_item_i2d didn't encode the OCTET STRING");
    }
    OPENSSL_free(out);
    ASN1_OCTET_STRING_free(octets);

    static const unsigned char abc_sha256[SHA256_DIGEST_LENGTH] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)"abc", 3, digest);
    if (memcmp(digest, abc_sha256, sizeof(digest)) != 0) {
        return fail("SHA256 gave the wrong digest");
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL) {
        return fail("SSL_CTX_new failed");
    }
    SSL_CTX_free(ctx);

    puts("consumer: ok");
    return 0;
}
