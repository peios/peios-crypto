"""The generator refuses bindings that don't classify every public export
exactly once, and algorithms that don't grade every digest and cipher.

    generator_test.py GENERATOR INPUTS BINDINGS ALGORITHMS PREFIX

INPUTS holds what the build's generator read: public.pre, crypto.syms
and ssl.syms.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

generator, inputs, bindings_path, algorithms_path, prefix = sys.argv[1:]
inputs = Path(inputs)
bindings = Path(bindings_path).read_text()
algorithms = Path(algorithms_path).read_text()
failures = 0


def run(bindings_text, algorithms_text):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "bindings.toml").write_text(bindings_text)
        (tmp / "algorithms.toml").write_text(algorithms_text)
        (tmp / "out").mkdir()
        return subprocess.run(
            [sys.executable, "-I", generator, prefix, inputs / "public.pre",
             inputs / "crypto.syms", inputs / "ssl.syms", tmp / "bindings.toml",
             tmp / "algorithms.toml", tmp / "out"],
            capture_output=True, text=True)


def expect(what, bindings_text, algorithms_text, refusal):
    global failures
    result = run(bindings_text, algorithms_text)
    if refusal is None:
        if result.returncode != 0:
            print(f"generator_test: {what}: refused:\n{result.stderr}")
            failures += 1
    elif result.returncode == 0 or refusal not in result.stderr:
        print(f"generator_test: {what}: not refused with {refusal!r}:\n{result.stderr}")
        failures += 1


def changed(text, old, new):
    if old not in text:
        sys.exit(f"generator_test: the files no longer contain {old!r}")
    return text.replace(old, new, 1)


FIRST_LIST = "functions = [\n"

expect("the real files", bindings, algorithms, None)
expect("a public function left out",
       changed(bindings, '    "EVP_DigestUpdate",\n', ""), algorithms,
       "doesn't classify these public exports")
expect("a name AWS-LC doesn't export",
       changed(bindings, FIRST_LIST, FIRST_LIST + '    "NOT_AN_AWSLC_FUNCTION",\n'), algorithms,
       "classifies names AWS-LC doesn't export")
expect("a function classified twice",
       changed(bindings, FIRST_LIST, FIRST_LIST + '    "EVP_DigestUpdate",\n'), algorithms,
       "is classified twice")
expect("a hooked function also classified",
       changed(bindings, FIRST_LIST, FIRST_LIST + '    "EVP_DigestInit_ex",\n'), algorithms,
       "is hooked and classified")
expect("a group with no reason",
       changed(bindings, 'reason = "', 'reason = "" # "'), algorithms,
       "gives no reason")
expect("a digest left ungraded",
       bindings, changed(algorithms, 'getter = "EVP_md5"\n', 'getter = "EVP_md5_gone"\n'),
       "doesn't grade these digests")

if failures == 0:
    print("generator_test: ok")
sys.exit(failures != 0)
