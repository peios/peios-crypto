"""Generates libpcrypto's and libpssl's forwarders, hooks, version scripts
and policy table.

    generate.py PREFIX PUBLIC.i CRYPTO_SYMS SSL_SYMS BINDINGS ALGORITHMS OUT

PUBLIC.i is AWS-LC's public headers, preprocessed as C and C++ with their
macros kept (`-E -dD`); CRYPTO_SYMS and SSL_SYMS are `readelf -sW` of
AWS-LC's prefixed archives; BINDINGS is `bindings.toml` and ALGORITHMS
`algorithms.toml`.

AWS-LC compiles with hidden visibility and gives its API default
visibility, so an archive's defined, default-visibility symbols are what a
library exports:

- A function named PREFIX_X is exported as X, by a forwarder that jumps to
  it, or by a hook that asks the policy runtime first.
- Data, which AWS-LC's build leaves unprefixed, is exported by its own
  name: a forwarder can't stand in for an address.
- libssl's C++ functions, in the namespace `bssl::PREFIX` or outside any
  namespace, are exported by their own names. No OpenSSL name is mangled.

Each is public if the public headers declare it: a C++ function, if they
declare the name that leads its own. The others are AWS-LC's internals,
which it exports for its own tests, and only the testing libraries export
them, in the version PEIOS_AWSLC_TESTING. libpcrypto also exports, in
PEIOS_AWSLC_PRIVATE, the prefixed names libssl's archive calls.

Every public export must be classified by BINDINGS exactly once, as
`forward`, `pending` or a hook, and every digest and cipher the public
headers offer must be graded by ALGORITHMS. The generator fails otherwise,
and on any symbol it can't place.
"""

import re
import sys
import tomllib
from pathlib import Path

GRADES = ["U", "D", "C", "B", "A"]
OPERATIONS = ["digest", "hmac", "cmac", "mac", "kdf", "drbg", "encrypt", "decrypt", "keygen",
              "sign", "verify", "derive", "encapsulate", "decapsulate"]
KINDS = {"digest": "EVP_MD", "cipher": "EVP_CIPHER", "aead": "EVP_AEAD", "rsa": None, "dh": None,
         "ec": None, "pqdsa": None, "kem": None, "fixed": None}
# Kinds graded by key size, and by a NID naming a curve or parameter set.
SIZED = {"rsa", "dh"}
NAMED = {"ec", "pqdsa", "kem"}
# Each method kind's struct tag, as AWS-LC's base.h typedefs it.
TAGS = {"digest": "env_md_st", "cipher": "evp_cipher_st", "aead": "evp_aead_st"}


def fail(message, items=()):
    print(f"generate.py: {message}", file=sys.stderr)
    for item in sorted(items)[:40]:
        print(f"    {item}", file=sys.stderr)
    sys.exit(1)


def identifiers(text):
    """The identifiers in preprocessed C, outside string and character
    literals: `#define SN_shake128 "SHAKE128"` doesn't declare SHAKE128."""
    text = re.sub(r'"(?:\\.|[^"\\\n])*"' + r"|'(?:\\.|[^'\\\n])*'", " ", text)
    return set(re.findall(r"[A-Za-z_]\w*", text))


def leading(name, namespace):
    """The name that leads a mangled C++ name, or None."""
    head = f"_ZN4bssl{len(namespace)}{namespace}"
    if name.startswith(head):
        rest = name[len(head):]
    elif re.match(r"_Z\d", name):
        rest = name[2:]
    else:
        return None
    digits = re.match(r"\d+", rest).group()
    return rest[len(digits):len(digits) + int(digits)]


def symbols(path, lib, prefix, public):
    """Each exported symbol as (kind, visibility, symbol, name), and the
    prefixed names the archive's members use and define."""
    exported, used, defined = [], set(), set()
    for line in Path(path).read_text().splitlines():
        f = line.split()
        if len(f) < 8 or not re.fullmatch(r"\d+:", f[0]):
            continue
        type_, bind, vis, ndx, sym = f[3], f[4], f[5], f[6], f[7]
        if bind not in ("GLOBAL", "WEAK"):
            continue
        if ndx == "UND":
            if sym.startswith(prefix + "_"):
                used.add(sym)
            continue
        if sym.startswith(prefix + "_"):
            defined.add(sym)
        if vis != "DEFAULT":
            continue
        if type_ == "FUNC" and sym.startswith(prefix + "_"):
            name = sym[len(prefix) + 1:]
            exported.append(("forward", name in public, sym, name))
        elif type_ == "OBJECT" and not sym.startswith((prefix + "_", "_Z")):
            exported.append(("export", sym in public, sym, sym))
        elif lib == "ssl" and type_ == "FUNC" and leading(sym, prefix):
            name = leading(sym, prefix)
            exported.append(("export", name in public, sym, name))
        else:
            fail(f"lib{lib} exports a symbol the generator can't place: {type_} {sym}")
    return sorted(set(exported)), used, defined


def parameters(signature, function):
    """The names of a hook's parameters, from its C signature."""
    match = re.fullmatch(rf"\s*(.+?)\b{function}\s*\((.*)\)\s*", signature, re.S)
    if not match:
        fail(f"hook {function}: can't read its signature: {signature}")
    params = match.group(2).strip()
    if params in ("", "void"):
        return []
    # Split at the commas outside parentheses and brackets, so that a
    # function pointer's own parameters stay with it.
    pieces, depth, start = [], 0, 0
    for i, char in enumerate(params):
        depth += char in "([" and 1 or char in ")]" and -1 or 0
        if char == "," and depth == 0:
            pieces.append(params[start:i])
            start = i + 1
    pieces.append(params[start:])
    names = []
    for param in pieces:
        if "..." in param:
            fail(f"hook {function}: variadic parameters aren't supported")
        pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", param)
        if pointer:
            names.append(pointer.group(1))
            continue
        name = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$", param)
        if not name:
            fail(f"hook {function}: unnamed parameter in {signature}")
        names.append(name.group(1))
    return names


def classify(bindings, public_names):
    """Each public name's class, from BINDINGS; the hooks by name."""
    classes, hooks = {}, {}
    for group in bindings.get("group", []):
        if group.get("class") not in ("forward", "pending"):
            fail(f"group {group.get('title')!r} has no class forward or pending")
        if not group.get("reason"):
            fail(f"group {group.get('title')!r} gives no reason")
        for name in group["functions"]:
            if name in classes:
                fail(f"{name} is classified twice")
            classes[name] = group["class"]
    for hook in bindings.get("hook", []):
        name = hook["function"]
        if name in classes:
            fail(f"{name} is hooked and classified as {classes[name]}")
        needed = ("signature", "wrap") if "wrap" in hook else ("signature", "policy", "failure")
        for key in needed:
            if key not in hook:
                fail(f"hook {name} gives no {key}")
        classes[name] = "hook"
        hooks[name] = hook
    unclassified = public_names - classes.keys()
    if unclassified:
        fail("bindings.toml doesn't classify these public exports:", unclassified)
    stale = classes.keys() - public_names
    if stale:
        fail("bindings.toml classifies names AWS-LC doesn't export:", stale)
    return classes, hooks


def getters(preprocessed, type_):
    pattern = rf"const\s+{type_}\s*\*\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*\(\s*void\s*\)"
    return set(re.findall(pattern, preprocessed))


def policy_table(algorithms, preprocessed, prefix):
    """The C table of algorithms.toml's grades, and each entry's index by
    its id, `md5.hmac` say."""
    rows, used, ids, index = [], {kind: set() for kind in TAGS}, set(), {}
    for alg in algorithms["algorithm"]:
        id_, kind = alg["id"], alg["kind"]
        if id_ in ids:
            fail(f"algorithms.toml lists {id_} twice")
        ids.add(id_)
        if kind not in KINDS:
            fail(f"algorithm {id_}: unknown kind {kind}")
        if kind in SIZED:
            low, high = alg["bits"]
            method = f".min_bits = {low}, .max_bits = {high}"
        elif kind in NAMED:
            if not re.fullmatch(r"NID_\w+", alg.get("nid", "")):
                fail(f"algorithm {id_}: a {kind} needs a nid, NID_X9_62_prime256v1 say")
            method = f".nid = {alg['nid']}"
        elif kind == "fixed":
            method = ".min_bits = 0"
        else:
            getter = alg["getter"]
            used[kind].add(getter)
            field = {"digest": "md", "cipher": "cipher", "aead": "aead"}[kind]
            method = f".{field} = {prefix}_{getter}"
        for op, grading in alg["operations"].items():
            if op not in OPERATIONS:
                fail(f"algorithm {id_}: unknown operation {op}")
            floor = grading.get("floor", False)
            grade = grading.get("grade", "U")
            if grade not in GRADES:
                fail(f"algorithm {id_}.{op}: unknown grade {grade}")
            if not floor and "grade" not in grading:
                fail(f"algorithm {id_}.{op} has no grade")
            index[f"{id_}.{op}"] = len(rows)
            rows.append(
                f'    {{.id = "{id_}.{op}", .name = "{id_}", .kind = PEIOS_KIND_{kind.upper()}, {method}, '
                f'.op = PEIOS_OP_{op.upper()}, .grade = PEIOS_GRADE_{grade}, '
                f'.fips = {int(grading.get("fips", False))}, .floor = {int(floor)}}},')
    for kind in TAGS:
        type_ = KINDS[kind]
        offered = getters(preprocessed, type_)
        if not offered:
            fail(f"found no {type_} getters in the public headers")
        ungraded = offered - used[kind]
        if ungraded:
            fail(f"algorithms.toml doesn't grade these {kind}s:", ungraded)
        unknown = used[kind] - offered
        if unknown:
            fail(f"algorithms.toml names {kind} getters the headers don't offer:", unknown)
    declarations = [
        f"extern const struct {tag} *{prefix}_{g}(void);"
        for kind, tag in TAGS.items()
        for g in sorted(used[kind])]
    return "\n".join([
        "/* Generated by generate.py from algorithms.toml. */",
        "#include <openssl/nid.h>",
        "",
        '#include "peios_policy.h"',
        "",
        *declarations,
        "",
        "const struct peios_algorithm peios_algorithms[] = {",
        *rows,
        "};",
        "",
        "const unsigned peios_algorithm_count =",
        "    sizeof(peios_algorithms) / sizeof(peios_algorithms[0]);",
        "",
    ]), index


def entry_macro(id_):
    return "PEIOS_ENTRY_" + re.sub(r"[^A-Za-z0-9]", "_", id_)


def policy_ids(index):
    """A header naming each entry by its id, for the runtime's own
    references, so that one to an entry algorithms.toml lacks fails to
    compile."""
    macros = {}
    for id_, i in index.items():
        macro = entry_macro(id_)
        if macro in macros:
            fail(f"algorithms.toml ids {macros[macro]} and {id_} make the same C name")
        macros[macro] = id_
    return "\n".join([
        "/* Generated by generate.py from algorithms.toml: each entry by its id. */",
        "#ifndef PEIOS_POLICY_IDS_H",
        "#define PEIOS_POLICY_IDS_H",
        '#include "peios_policy.h"',
        "",
        *(f"#define {entry_macro(id_)} (&peios_algorithms[{i}])" for id_, i in index.items()),
        "",
        "#endif",
        "",
    ])


def policy_expression(hook, name, index):
    """A hook's policy expression, each `@id` made the address of
    algorithms.toml's entry for it."""
    def entry(match):
        id_ = match.group(1)
        if id_ not in index:
            fail(f"hook {name}: algorithms.toml grades no {id_}")
        return f"&peios_algorithms[{index[id_]}]"
    return re.sub(r"@([a-z0-9-]+\.[a-z]+)", entry, hook["policy"])


def hooks_source(hooks, prefix, headers, index):
    out = [
        "/* Generated by generate.py from bindings.toml: libpcrypto's and",
        "   libpssl's hooked functions, each asking the policy runtime before",
        "   it calls AWS-LC. Compiled against AWS-LC's unprefixed headers, so",
        "   each definition is checked against AWS-LC's own declaration.",
        "   Deprecated functions are hooked too, deliberately. */",
        '#pragma GCC diagnostic ignored "-Wdeprecated-declarations"',
        *headers,
        '#include "peios_policy.h"',
        "",
    ]
    for name, hook in sorted(hooks.items()):
        names = parameters(hook["signature"], name)
        returns_void = re.match(r"\s*void\s+[A-Za-z_]", hook["signature"]) is not None
        if "wrap" in hook:
            # The runtime makes the whole call, deciding by what AWS-LC
            # produces or accepts.
            call = f"{hook['wrap']}({', '.join(names)});"
            out += [
                f"{hook['signature'].strip()} {{",
                f"    {call}" if returns_void else f"    return {call}",
                "}",
                "",
            ]
            continue
        failure = hook["failure"]
        if returns_void and failure != "abort":
            fail(f"hook {name} returns nothing, so a refusal must abort")
        if failure == "abort":
            refuse = f'        peios_policy_abort("{name}");'
        else:
            refuse = f"        return {failure};"
        call = f"{prefix}_{name}({', '.join(names)});"
        out += [
            f"extern __typeof__({name}) {prefix}_{name};",
            "",
            f"{hook['signature'].strip()} {{",
            f"    if (!({policy_expression(hook, name, index)})) {{",
            refuse,
            "    }",
            f"    {call}" if returns_void else f"    return {call}",
            "}",
            "",
        ]
    return "\n".join(out)


def forwarders(entries, hooked, prefix):
    out = ["\t.text"]
    for kind, _, sym, name in entries:
        if kind != "forward" or name in hooked:
            continue
        out += [
            "", f"\t.globl {name}", f"\t.type {name}, @function", "\t.p2align 4", f"{name}:",
            "\tendbr64", f"\tjmp {sym}@PLT", f"\t.size {name}, .-{name}",
        ]
    out += [
        "", '\t.section .note.GNU-stack,"",@progbits',
        '\t.section .note.gnu.property,"a"', "\t.p2align 3",
        "\t.long 4, 16, 5", '\t.asciz "GNU"', "\t.long 0xc0000002, 4, 3", "\t.p2align 3", "",
    ]
    return "\n".join(out)


def node(version, names, local=False):
    lines = [f"{version} {{", "  global:", *(f"    {n};" for n in sorted(names))]
    if local:
        lines += ["  local:", "    *;"]
    return "\n".join(lines + ["};", ""])


def main():
    prefix, public_i, crypto_syms, ssl_syms, bindings_path, algorithms_path, out = sys.argv[1:]
    out = Path(out)
    preprocessed = Path(public_i).read_text()
    public = identifiers("\n".join(
        line for line in preprocessed.splitlines() if not re.match(r"# \d", line)))

    libs = {}
    for lib, path in (("crypto", crypto_syms), ("ssl", ssl_syms)):
        libs[lib] = symbols(path, lib, prefix, public)

    public_names = {name for lib in libs.values() for _, pub, _, name in lib[0] if pub}
    bindings = tomllib.loads(Path(bindings_path).read_text())
    classes, hooks = classify(bindings, public_names)
    for name in hooks:
        kinds = {kind for lib in libs.values() for kind, _, _, n in lib[0] if n == name}
        if kinds != {"forward"}:
            fail(f"hook {name} isn't a C function AWS-LC exports")

    headers = sorted(set(re.findall(r'^# \d+ "[^"]*/include/(openssl/[^"]+\.h)"', preprocessed, re.M)))
    headers = [f"#include <{h}>" for h in headers if "boringssl_prefix_symbols" not in h]
    algorithms = tomllib.loads(Path(algorithms_path).read_text())
    table, index = policy_table(algorithms, preprocessed, prefix)
    (out / "policy-table.c").write_text(table)
    (out / "policy_ids.h").write_text(policy_ids(index))
    for lib, (entries, _, _) in libs.items():
        own = {n: h for n, h in hooks.items() if any(name == n for _, _, _, name in entries)}
        (out / f"{lib}-hooks.c").write_text(hooks_source(own, prefix, headers, index))

    for lib, (entries, _, _) in libs.items():
        (out / f"{lib}-forwarders.S").write_text(forwarders(entries, hooks, prefix))

    crypto_entries = libs["crypto"][0]
    _, ssl_used, ssl_defined = libs["ssl"]
    needed = ssl_used - ssl_defined
    missing = needed - {sym for kind, _, sym, _ in crypto_entries if kind == "forward"}
    if missing:
        fail("libssl calls prefixed names libcrypto doesn't export:", missing)

    for lib, version in (("crypto", "PCRYPTO_1"), ("ssl", "PSSL_1")):
        entries = libs[lib][0]
        # A C++ symbol is exported by its mangled name, not its leading one.
        exported = sorted({(s if s.startswith("_Z") else n) for _, pub, s, n in entries if pub})
        shipped = node(version, exported, local=True)
        testing = node("PEIOS_AWSLC_TESTING", sorted(
            {(s if s.startswith("_Z") else n) for _, pub, s, n in entries if not pub}))
        private = node("PEIOS_AWSLC_PRIVATE", needed) if lib == "crypto" else ""
        (out / f"{lib}.map").write_text(shipped + private)
        (out / f"{lib}-testing.map").write_text(shipped + private + testing)

    counts = {c: sum(1 for v in classes.values() if v == c) for c in ("forward", "pending", "hook")}
    print(f"generate.py: {len(classes)} public functions: {counts['forward']} forwarded, "
          f"{counts['hook']} hooked, {counts['pending']} pending a hook")


if __name__ == "__main__":
    main()
