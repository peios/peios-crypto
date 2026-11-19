#!/bin/sh
# Generates libpcrypto's and libpssl's forwarders and version scripts from
# the symbol tables of AWS-LC's prefixed archives, as `readelf -sW` prints
# them:
#
#   generate-forwarders.sh PREFIX CRYPTO_SYMS SSL_SYMS OUT
#
# AWS-LC compiles with hidden visibility and gives its API default
# visibility, so an archive's defined, default-visibility symbols are what a
# library exports. Each is classified, and the generator fails on any it
# can't:
#
# - A function named PREFIX_X is exported as X, by a forwarder that jumps to
#   it.
# - Data, which AWS-LC's build leaves unprefixed, is exported by its own
#   name: a forwarder can't stand in for an address.
# - libssl's C++ internals, in the namespace `bssl::PREFIX`, are exported by
#   their own names, and so is `tls_print_all_supported_cipher_suites`, the
#   one C++ function outside it. No OpenSSL name is mangled.
#
# libpcrypto also exports, in the version PEIOS_AWSLC_PRIVATE, the prefixed
# names libssl's archive calls. Nothing else of AWS-LC is exported.
#
# It writes OUT/crypto-forwarders.S, OUT/crypto.map, OUT/ssl-forwarders.S
# and OUT/ssl.map.
set -eu

prefix=$1
crypto_syms=$2
ssl_syms=$3
out=$4

export LC_ALL=C

# Prints "KIND NAME" for each exported symbol in a symbol table, where KIND
# is `forward`, `export` or `unclassified`; with `used` and `defined`, the
# prefixed names its members use and define, at any visibility.
classify() {
    awk -v prefix="${prefix}_" -v namespace="$prefix" -v lib="$1" '
        $1 ~ /^[0-9]+:$/ && NF >= 8 {
            type = $4; bind = $5; vis = $6; ndx = $7; name = $8
            if (bind != "GLOBAL" && bind != "WEAK") next
            if (ndx == "UND") {
                if (index(name, prefix) == 1) print "used", name
                next
            }
            if (index(name, prefix) == 1) print "defined", name
            if (vis != "DEFAULT") next
            if (type == "FUNC" && index(name, prefix) == 1) {
                print "forward", name
            } else if (type == "OBJECT" && index(name, prefix) != 1 && name !~ /^_Z/) {
                print "export", name
            } else if (lib == "ssl" && name ~ ("^_ZN4bssl[0-9]+" namespace)) {
                print "export", name
            } else if (lib == "ssl" && name == "_Z37tls_print_all_supported_cipher_suitesb") {
                print "export", name
            } else {
                print "unclassified", type, name
            }
        }' "$2" | sort -u
}

classify crypto "$crypto_syms" > "$out/crypto.classes"
classify ssl "$ssl_syms" > "$out/ssl.classes"

if grep -h '^unclassified ' "$out/crypto.classes" "$out/ssl.classes" > "$out/unclassified"; then
    echo "AWS-LC exports symbols the generator can't classify:" >&2
    cat "$out/unclassified" >&2
    exit 1
fi

# Writes a library's forwarders, with the note that marks them as compiled
# for IBT and SHSTK.
forwarders() {
    {
        printf '\t.text\n'
        awk -v n="${#prefix}" '$1 == "forward" {
            public = substr($2, n + 2)
            printf "\n\t.globl %s\n\t.type %s, @function\n\t.p2align 4\n%s:\n", public, public, public
            printf "\tendbr64\n\tjmp %s@PLT\n\t.size %s, .-%s\n", $2, public, public
        }' "$1"
        printf '\n\t.section .note.GNU-stack,"",@progbits\n'
        printf '\t.section .note.gnu.property,"a"\n\t.p2align 3\n'
        printf '\t.long 4, 16, 5\n\t.asciz "GNU"\n'
        printf '\t.long 0xc0000002, 4, 3\n\t.p2align 3\n'
    } > "$2"
}

# Writes a library's version script: VERSION holds its exports, and every
# other symbol is local.
version_script() {
    {
        printf '%s {\n  global:\n' "$2"
        awk -v n="${#prefix}" '
            $1 == "forward" { print "    " substr($2, n + 2) ";" }
            $1 == "export" { print "    " $2 ";" }' "$1" | sort
        printf '  local:\n    *;\n};\n'
    } > "$3"
}

forwarders "$out/crypto.classes" "$out/crypto-forwarders.S"
forwarders "$out/ssl.classes" "$out/ssl-forwarders.S"
version_script "$out/crypto.classes" PCRYPTO_1 "$out/crypto.map"
version_script "$out/ssl.classes" PSSL_1 "$out/ssl.map"

# The prefixed names libssl calls but doesn't define, each of which
# libpcrypto must export.
awk '$1 == "used" { print $2 }' "$out/ssl.classes" | sort -u > "$out/ssl.used"
awk '$1 == "defined" { print $2 }' "$out/ssl.classes" | sort -u > "$out/ssl.defined"
comm -23 "$out/ssl.used" "$out/ssl.defined" > "$out/ssl.needed"
awk '$1 == "forward" { print $2 }' "$out/crypto.classes" | sort -u > "$out/crypto.defined"
missing=$(comm -23 "$out/ssl.needed" "$out/crypto.defined")
if [ -n "$missing" ]; then
    echo "libssl calls prefixed names libcrypto doesn't export:" >&2
    echo "$missing" >&2
    exit 1
fi
{
    printf 'PEIOS_AWSLC_PRIVATE {\n  global:\n'
    sed 's/.*/    &;/' "$out/ssl.needed"
    printf '};\n'
} >> "$out/crypto.map"
