#!/bin/sh
# Generates libpcrypto's and libpssl's forwarders and version scripts from
# the symbol tables of AWS-LC's prefixed archives, as `readelf -sW` prints
# them, and the identifiers AWS-LC's public headers declare, one per line:
#
#   generate-forwarders.sh PREFIX PUBLIC CRYPTO_SYMS SSL_SYMS OUT
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
# - libssl's C++ functions, in the namespace `bssl::PREFIX` or outside any
#   namespace, are exported by their own names. No OpenSSL name is mangled.
#
# Each is public if its public headers declare it: for a C++ function, if
# they declare the name that leads its own. Others are AWS-LC's internals,
# which it exports only for its own tests to call, and are exported only by
# the testing libraries, in the version PEIOS_AWSLC_TESTING: many are
# primitives no policy could govern.
#
# libpcrypto also exports, in the version PEIOS_AWSLC_PRIVATE, the prefixed
# names libssl's archive calls. Nothing else of AWS-LC is exported.
#
# It writes OUT/crypto-forwarders.S and OUT/ssl-forwarders.S, the version
# scripts OUT/crypto.map and OUT/ssl.map, and the testing libraries'
# OUT/crypto-testing.map and OUT/ssl-testing.map.
set -eu

prefix=$1
public=$2
crypto_syms=$3
ssl_syms=$4
out=$5

export LC_ALL=C

# Prints "KIND VISIBILITY NAME" for each exported symbol in a symbol table,
# where KIND is `forward` or `export` and VISIBILITY `public` or `testing`,
# or "unclassified TYPE NAME"; and, as "used NAME" and "defined NAME", the
# prefixed names its members use and define, at any visibility.
classify() {
    awk -v prefix="${prefix}_" -v namespace="$prefix" -v lib="$1" '
        # The name that leads a mangled C++ name: its first component after
        # `bssl::PREFIX`, or its whole name outside any namespace.
        function leading(name,    rest, digits) {
            rest = name
            if (index(rest, "_ZN4bssl" length(namespace) namespace) == 1) {
                rest = substr(rest, length("_ZN4bssl" length(namespace) namespace) + 1)
            } else if (rest ~ /^_Z[0-9]/) {
                rest = substr(rest, 3)
            } else {
                return ""
            }
            match(rest, /^[0-9]+/)
            digits = substr(rest, 1, RLENGTH)
            return substr(rest, RLENGTH + 1, digits + 0)
        }
        function visibility(name) {
            return (name in declared) ? "public" : "testing"
        }
        FILENAME == public { declared[$1] = 1; next }
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
                print "forward", visibility(substr(name, length(prefix) + 1)), name
            } else if (type == "OBJECT" && index(name, prefix) != 1 && name !~ /^_Z/) {
                print "export", visibility(name), name
            } else if (lib == "ssl" && type == "FUNC" && leading(name) != "") {
                print "export", visibility(leading(name)), name
            } else {
                print "unclassified", type, name
            }
        }' public="$public" "$public" "$2" | sort -u
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
            public = substr($3, n + 2)
            printf "\n\t.globl %s\n\t.type %s, @function\n\t.p2align 4\n%s:\n", public, public, public
            printf "\tendbr64\n\tjmp %s@PLT\n\t.size %s, .-%s\n", $3, public, public
        }' "$1"
        printf '\n\t.section .note.GNU-stack,"",@progbits\n'
        printf '\t.section .note.gnu.property,"a"\n\t.p2align 3\n'
        printf '\t.long 4, 16, 5\n\t.asciz "GNU"\n'
        printf '\t.long 0xc0000002, 4, 3\n\t.p2align 3\n'
    } > "$2"
}

# Prints, for a version script, the exported names of a library's symbols
# of VISIBILITY.
exported() {
    awk -v n="${#prefix}" -v visibility="$2" '
        $1 == "forward" && $2 == visibility { print "    " substr($3, n + 2) ";" }
        $1 == "export" && $2 == visibility { print "    " $3 ";" }' "$1" | sort
}

# Writes a library's version script: VERSION holds its public exports, and
# every other symbol is local.
version_script() {
    {
        printf '%s {\n  global:\n' "$2"
        exported "$1" public
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
awk '$1 == "forward" { print $3 }' "$out/crypto.classes" | sort -u > "$out/crypto.defined"
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

# The testing libraries' version scripts: the same, and their internals.
for lib in crypto ssl; do
    {
        cat "$out/$lib.map"
        printf 'PEIOS_AWSLC_TESTING {\n  global:\n'
        exported "$out/$lib.classes" testing
        printf '};\n'
    } > "$out/$lib-testing.map"
done
