# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
"""Tests for edl2codeql.py.

    python3 -m unittest discover -s scripts/tests

The corpus tests use an Open Enclave checkout ($OE_SRC, default: sut/openenclave
of this repository) and an oeedger8r binary ($OEEDGER8R or PATH); they are
skipped when those are missing.
"""
import contextlib
import glob
import io
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.abspath(os.path.join(SCRIPTS, *[os.pardir] * 4))
sys.path.insert(0, SCRIPTS)

import edl2codeql as E  # noqa: E402
from edl2codeql import (Decl, Edl, EdlError, Enum, Function, Import, Include,  # noqa: E402
                        Program, Struct, Type)

try:
    import yaml
except ImportError:
    yaml = None

OE_SRC = os.environ.get("OE_SRC", os.path.join(REPO, "sut", "openenclave"))
OE_INCLUDE = os.path.join(OE_SRC, "include")
OEEDGER8R = os.environ.get("OEEDGER8R") or shutil.which("oeedger8r")
SYSTEM_EDLS = ["openenclave/edl/core.edl", "openenclave/edl/sgx/platform.edl",
               "openenclave/edl/syscall.edl"]


def parse(text, defines=()):
    return E.parse(textwrap.dedent(text), "t.edl", frozenset(defines))


def enclave(body):
    return "enclave {\n" + textwrap.dedent(body) + "\n};\n"


def program(files, roots=("main.edl",), **options):
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            path = os.path.join(d, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(textwrap.dedent(text))
        search = [os.path.join(d, p) for p in options.pop("search_paths", [""])]
        return Program([os.path.join(d, r) for r in roots], search, **options)


def rows(body):
    p = program({"main.edl": enclave(body)})
    return {(f, path, kind) for _, f, path, kind in E.model_rows(p)}


class ParserTest(unittest.TestCase):
    def test_ast(self):
        tree = parse("""
            enclave {
                include "stdint.h"
                import "a.edl"
                from "b.edl" import *;
                from "c.edl" import f, g,;
                enum color { RED, GREEN = 2, BLUE = GREEN, };
                enum { ANONYMOUS };
                struct S { [count=n] const int* p; size_t n };
                union U { int i; float f; };
                trusted {
                    public int e([in, size=len] void* buf, size_t len, int a[4][N])
                        transition_using_threads;
                };
                untrusted {
                    unsigned long long o([in, string,] char* s) allow(e)
                        propagate_errno transition_using_threads;
                    struct S** p(unsigned u, long int l, short int s, char int c, long double d,
                                 const enum color c2);
                    void q(void);
                };
            };
        """)
        self.assertEqual(tree, Edl("t.edl", (
            Include("stdint.h"), Import("a.edl", None), Import("b.edl", None),
            Import("c.edl", ("f", "g")), Enum("color", ("RED", "GREEN", "BLUE")),
            Enum(None, ("ANONYMOUS",)),
            Struct("struct", "S", (Decl("p", Type("int", const=True, ptr=1), count="n"),
                                   Decl("n", Type("size_t")))),
            Struct("union", "U", (Decl("i", Type("int")), Decl("f", Type("float")))),
            Function("e", Type("int"), (Decl("buf", Type("void", ptr=1), frozenset({"in"}), "len"),
                                        Decl("len", Type("size_t")),
                                        Decl("a", Type("int"), dims=(4, "N"))),
                     True, switchless=True),
            Function("o", Type("unsigned long long"),
                     (Decl("s", Type("char", ptr=1), frozenset({"in", "string"})),),
                     False, ("e",), True, True),
            Function("p", Type("S", "struct", ptr=2),
                     (Decl("u", Type("unsigned int")), Decl("l", Type("long")),
                      Decl("s", Type("short")), Decl("c", Type("char")),
                      Decl("d", Type("long double")), Decl("c2", Type("color", "enum", True))),
                     False),
            Function("q", Type("void"), (), False),
        )))
        f = tree.items[-4]
        self.assertEqual(f.loc, ("t.edl", 12, 20))
        self.assertEqual([p.c_type for p in f.params], ["void*", "size_t", "int[4][N]"])
        self.assertEqual([p.attributes for p in f.params], ["in,size=len", "", ""])
        self.assertEqual(f.flags, "public,transition_using_threads")

    def test_preprocessor(self):
        text = "enclave { #ifdef A struct a {int x;}; #ifndef B struct b {int x;}; #else " \
               "struct c {int x;}; #endif #endif # ifdef C struct d {int x;}; # endif };"
        cases = {(): [], ("A",): ["a", "b"], ("A", "B", "C"): ["a", "c", "d"]}
        for defines, expected in cases.items():
            self.assertEqual([s.name for s in parse(text, defines).items], expected, defines)

    def test_oeedger8r_quirks(self):
        accepted = ["trusted { public void f(unsigned x, char int y); };",
                    "struct S { int a; int b };",  # the last ';' is optional
                    "trusted { public void f([in,] int* p,); };",
                    "untrusted { void f() transition_using_threads propagate_errno; };",
                    "enum { A, };"]
        for body in accepted:
            parse(enclave(body))
        parse("enclave { }; tokens after the enclave are ignored")
        rejected = {"trusted { public void f(long long int x); };": "expected ','",
                    "trusted { public void f(unsigned long double x); };": "unsigned long double",
                    "trusted { void f(void); };": "must be 'public'",
                    "trusted { public void f(void) allow(g); };": "'allow' is invalid",
                    "trusted { public void f(void) propagate_errno; };": "expected ';'"}
        for body, message in rejected.items():
            with self.assertRaisesRegex(EdlError, message, msg=body):
                parse(enclave(body))

    def test_errors(self):
        cases = {
            "enclave {\n  /* open": "t.edl:2:3: error: unterminated comment",
            'enclave { include "x': "t.edl:1:19: error: unterminated string",
            "enclave { @": "t.edl:1:11: error: unexpected character '@'",
            "enclave { struct S { [count=0x10] int* p; }; };": "1:29: error: invalid integer",
            "enclave { struct S { [in] int* p; }; };": "attribute 'in' is not allowed here",
            "enclave { union U { [count=1] int* p; }; };": "'count' is not allowed here",
            "enclave { trusted { public void f([bogus] int* p); }; };": "unknown attribute",
            "enclave { trusted { public void f([in, in] int* p); }; };": "duplicated attribute",
            "enclave { trusted { public void f([] int* p); }; };": "empty attribute list",
            "enclave { trusted { public void f([,] int* p); }; };": "expected an attribute",
            "enclave { trusted { public void f(int a b); }; };": "1:41: error: expected ','",
            "enclave { struct S { int x y; }; };": "1:28: error: expected ';', got 'y'",
            "enclave { trusted { public void f(void) }; };": "after the declaration of 'f'",
            "enclave { blah };": "unexpected 'blah'",
            "enclave {": "unexpected end of file",
            "enclave { #if X\n#endif };": "unsupported directive #if",
            "enclave { #else };": "#else without #ifdef",
            "enclave { #ifdef X #else #else #endif };": "#else without #ifdef",
            "enclave {\n#ifdef X };": "t.edl:2:1: error: unterminated #ifdef",
        }
        for text, message in cases.items():
            with self.assertRaises(EdlError, msg=text) as cm:
                parse(text)
            self.assertIn(message, str(cm.exception), text)
        parse("enclave { #ifdef X [count=0x10] #endif };")  # excluded tokens are only lexed


class ImportTest(unittest.TestCase):
    def test_semantics(self):
        p = program({
            "lib.edl": enclave("""
                struct T { int x; };
                trusted { public void l1(void); public void l2(void); };
                untrusted { void l3(void); };
            """),
            "a.edl": enclave('import "lib.edl"'),
            "b.edl": enclave('from "lib.edl" import *;'),
            "main.edl": enclave("""
                import "a.edl"
                import "b.edl"
                from "lib.edl" import l2, l3;
                trusted { public void m(T t); };
            """),
            "only.edl": enclave('from "lib.edl" import l3;'),
        }, roots=("main.edl", "only.edl"))
        self.assertEqual(set(p.functions), {"m", "l1", "l2", "l3"})
        self.assertEqual(set(p.types), {"T"})
        self.assertEqual(sorted(m.name for m in p.modules.values()),
                         ["a.edl", "b.edl", "lib.edl", "main.edl", "only.edl"])

    def test_resolution(self):
        p = program({
            "inc/openenclave/edl/sgx/platform.edl": enclave("trusted { public void p(void); };"),
            "app/main.edl": enclave('from "platform.edl" import *;\nimport "local.edl"'),
            "app/local.edl": enclave("untrusted { void l(void); };"),
        }, roots=("app/main.edl",), search_paths=["inc"])
        self.assertEqual(set(p.functions), {"p", "l"})
        self.assertIn("openenclave/edl/sgx/platform.edl", [m.name for m in p.modules.values()])

    def test_errors(self):
        files = {
            "c.edl": enclave("trusted { public void c(void); };"),
            "same.edl": enclave("trusted { public void c(void); };"),
            "dup.edl": enclave('import "c.edl"\nimport "same.edl"'),
            "types.edl": enclave("struct S { int x; }; struct S { int x; };"),
            "r1.edl": enclave('import "r2.edl"'),
            "r2.edl": enclave('import "r1.edl"'),
            "missing.edl": enclave('import "nope.edl"'),
            "unknown.edl": enclave('from "c.edl" import zz;'),
        }
        for root, message in [("dup.edl", "duplicate definition of 'c'"),
                              ("types.edl", "duplicate definition of 'S'"),
                              ("r1.edl", "recursive import: r1.edl -> r2.edl -> r1.edl"),
                              ("missing.edl", "cannot find EDL file 'nope.edl'"),
                              ("unknown.edl", "function 'zz' not found in 'c.edl'")]:
            with self.assertRaisesRegex(EdlError, re.escape(message)):
                program(files, roots=(root,))


class ModelTest(unittest.TestCase):
    def test_ecall_parameters(self):
        self.assertEqual(rows("""
            trusted {
                public int f(int v, [in, size=n] void* in_buf, size_t n, [out] int* out,
                             [in, out] int* io, [user_check] char* uc, char* raw, int arr[4],
                             [in, string] const char* s, [in, isary] arr_t a);
            };
        """), {("f", p, k) for p, k in [
            ("Parameter[0]", "remote"), ("Parameter[0]", "oe-ecall-input"),
            ("Parameter[*1]", "remote"), ("Parameter[*1]", "oe-ecall-input"),
            ("Parameter[2]", "remote"), ("Parameter[2]", "oe-ecall-input"),
            ("Parameter[*4]", "remote"), ("Parameter[*4]", "oe-ecall-input"),
            ("Parameter[5]", "oe-host-pointer"), ("Parameter[*5]", "remote"),
            ("Parameter[6]", "oe-host-pointer"), ("Parameter[*6]", "remote"),
            ("Parameter[7]", "oe-host-pointer"), ("Parameter[*7]", "remote"),
            ("Parameter[*8]", "remote"), ("Parameter[*8]", "oe-ecall-input"),
            ("Parameter[*9]", "remote"), ("Parameter[*9]", "oe-ecall-input")]})

    def test_ocall_parameters(self):
        disclosed = ("oe-host-disclosure", "remote-sink")
        self.assertEqual(rows("""
            untrusted {
                void* o(int v, [in, size=n] const void* in_buf, size_t n, [out] int* out,
                        [in, out] int* io, [user_check] void* uc, [out, count=2] char** ptrs);
                void v(int x);
            };
        """), {("o", "Argument[*0]", "remote"), ("o", "Argument[*0]", "oe-ocall-output"),
               ("o", "Argument[*0]", "oe-host-pointer"), ("o", "Argument[**0]", "remote"),
               *(("o", p, k) for p in ("Argument[1]", "Argument[*2]", "Argument[3]",
                                       "Argument[*5]", "Argument[6]") for k in disclosed),
               ("o", "Argument[*4]", "remote"), ("o", "Argument[*4]", "oe-ocall-output"),
               ("o", "Argument[*5]", "remote"), ("o", "Argument[*5]", "oe-ocall-output"),
               ("o", "Argument[*7]", "remote"), ("o", "Argument[*7]", "oe-ocall-output"),
               ("o", "Argument[*7]", "oe-host-pointer"), ("o", "Argument[**7]", "remote"),
               *(("v", "Argument[0]", k) for k in disclosed)})

    def test_members_follow_deep_copy(self):
        found = rows("""
            struct Inner { [count=k] uint8_t* data; size_t k; };
            struct Outer {
                size_t len;
                [size=len] char* buf;
                char* raw;
                [count=1] Inner* inner;
                struct Inner by_value;
                uint8_t tag[4];
            };
            union U { void* p; int fd; };
            trusted { public void e([in] Outer* o); };
            untrusted { void o([out] U* u, [in] const struct Outer* out); };
        """)
        o = "Parameter[*0]"
        expected = {
            (o, "oe-ecall-input"), (f"{o}.Field[Outer::len]", "oe-ecall-input"),
            (f"{o}.Field[*Outer::buf]", "oe-ecall-input"),
            (f"{o}.Field[Outer::raw]", "oe-host-pointer"), (f"{o}.Field[*Outer::raw]", "remote"),
            (f"{o}.Field[*Outer::inner]", "oe-ecall-input"),
            (f"{o}.Field[*Outer::inner].Field[*Inner::data]", "oe-ecall-input"),
            (f"{o}.Field[*Outer::inner].Field[Inner::k]", "oe-ecall-input"),
            (f"{o}.Field[Outer::by_value].Field[Inner::data]", "oe-host-pointer"),
            (f"{o}.Field[Outer::tag]", "oe-ecall-input"),
        }
        self.assertLessEqual({("e", *r) for r in expected}, found)
        self.assertNotIn(("e", f"{o}.Field[Outer::buf]", "oe-host-pointer"), found)
        self.assertLessEqual({("o", "Argument[*0].Field[U::p]", "oe-host-pointer"),
                              ("o", "Argument[*0].Field[U::fd]", "oe-ocall-output"),
                              ("o", "Argument[*1].Field[*Outer::buf]", "oe-host-disclosure"),
                              ("o", "Argument[*1].Field[Outer::raw]", "oe-host-disclosure")}, found)

    def test_recursive_struct(self):
        found = rows("""
            struct Node { int v; [count=1] Node* next; };
            trusted { public void e([in] Node* n); };
        """)
        self.assertIn(("e", "Parameter[*0].Field[*Node::next]", "remote"), found)
        self.assertNotIn(("e", "Parameter[*0].Field[*Node::next].Field[Node::v]", "remote"), found)

    @unittest.skipIf(yaml is None, "PyYAML is not installed")
    def test_yaml(self):
        p = program({"main.edl": enclave("""
            trusted { public int e([in, string] const char* name) transition_using_threads; };
            untrusted { ssize_t o([out, size=n] void* buf, size_t n) propagate_errno; };
        """)})
        text = E.render(p, E.model_rows(p))
        self.assertEqual(text, E.render(p, E.model_rows(p)))
        tables = {b["addsTo"]["extensible"]: b for b in yaml.safe_load(text)["extensions"]}
        self.assertEqual(tables["sourceModel"]["addsTo"]["pack"], "codeql/cpp-all")
        self.assertTrue(all(len(r) == 9 and r[2] is False
                            for t in ("sourceModel", "sinkModel") for r in tables[t]["data"]))
        self.assertEqual(tables["oeEdlFunction"]["data"],
                         [["e", "trusted", "int", "public,transition_using_threads"],
                          ["o", "untrusted", "ssize_t", "propagate_errno"]])
        self.assertEqual(tables["oeEdlParameter"]["data"],
                         [["e", 0, "name", "const char*", "in,string"],
                          ["o", 0, "buf", "void*", "out,size=n"], ["o", 1, "n", "size_t", ""]])


class LintTest(unittest.TestCase):
    def findings(self, body):
        return {(rule, msg.split(": ", 1)[0]) for _, rule, msg in
                E.lint(program({"main.edl": enclave(body)}))}

    def test_rules(self):
        self.assertEqual({rule for rule, _ in self.findings("""
            struct S { char* raw; [count=1] int* ok; };
            trusted {
                public char* e([user_check] void* uc, int* raw, [in] S* s, [in, count=n] char** pp,
                               int n);
            };
            untrusted {
                void* o([out] S* s);
                int read_ocall([in, out, size=n] void* buf, size_t n, [out, size=1] uint32_t* len);
            };
        """)}, {"ecall-user-check", "ecall-unannotated-pointer", "ecall-embedded-host-pointer",
                "ecall-returns-pointer", "ocall-returns-pointer", "ocall-embedded-host-pointer",
                "ocall-inout-read", "size-smaller-than-type", "signed-size"})

    def test_safe_interface(self):
        self.assertEqual(self.findings("""
            struct S { size_t n; [count=n] int* p; };
            trusted { public int e([in] S* s, [in, string] const char* name); };
            untrusted { int write_ocall([in, size=n] const void* buf, size_t n); };
        """), set())


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = E.main(list(args))
        return status, out.getvalue(), err.getvalue()

    def test_generate_check_lint(self):
        with tempfile.TemporaryDirectory() as d:
            edl, model = os.path.join(d, "main.edl"), os.path.join(d, "out", "m.model.yml")
            with open(edl, "w") as f:
                f.write(enclave("untrusted { void* leak(void); };"))
            self.assertEqual(self.run_cli(edl, "--out", model)[0], 0)
            self.assertEqual(self.run_cli(edl, "--out", model, "--check")[0], 0)
            with open(model, "a") as f:
                f.write("# edited\n")
            status, _, err = self.run_cli(edl, "--out", model, "--check")
            self.assertEqual((status, "out of date" in err), (1, True))
            status, out, _ = self.run_cli(edl, "--lint")
            self.assertEqual((status, out.count("\n")), (0, 1))
            self.assertIn("[ocall-returns-pointer]", out)
            self.assertIn("Function(name='leak'", self.run_cli(edl, "--dump-ast")[1])
            self.assertIn("extensions:", self.run_cli(edl)[1])

    def test_errors_prevent_output(self):
        with tempfile.TemporaryDirectory() as d:
            edl, model = os.path.join(d, "main.edl"), os.path.join(d, "m.model.yml")
            with open(edl, "w") as f:
                f.write("enclave { trusted { void f(void); }; };")
            status, _, err = self.run_cli(edl, "--out", model)
            self.assertEqual((status, os.path.exists(model)), (1, False))
            self.assertIn("main.edl:1:21: error: trusted functions must be 'public'", err)


def corpus():
    return sorted(p for p in glob.glob(os.path.join(OE_SRC, "**", "*.edl"), recursive=True)
                  if "/3rdparty/" not in p)


def search_paths(edl):
    return [os.path.dirname(edl), OE_INCLUDE, os.path.join(OE_INCLUDE, "openenclave", "edl"),
            os.path.join(OE_INCLUDE, "openenclave", "edl", "sgx")]


@unittest.skipUnless(os.path.isfile(os.path.join(OE_INCLUDE, SYSTEM_EDLS[0])),
                     "no Open Enclave checkout (set OE_SRC)")
class CorpusTest(unittest.TestCase):
    def test_system_edls(self):
        p = Program([os.path.join(OE_INCLUDE, e) for e in SYSTEM_EDLS], [OE_INCLUDE],
                    ["OE_SGX_ENTROPY"])
        self.assertGreater(len(p.functions), 90)
        found = {(f, path, kind) for _, f, path, kind in E.model_rows(p)}
        # The members used by test/cpp/sgx/edl_models.c.
        self.assertLessEqual({
            ("oe_syscall_fstat_ocall", "Argument[*2].Field[oe_stat_t::st_size]", "oe-ocall-output"),
            ("oe_get_public_key_ecall",
             "Parameter[*0].Field[oe_asymmetric_key_params_t::user_data_size]", "oe-ecall-input"),
            ("oe_syscall_connect_ocall", "Argument[*2].Field[oe_sockaddr::sa_family]",
             "oe-host-disclosure")}, found)

    def test_mutations_never_crash(self):
        rng = random.Random(1234)
        files = corpus()
        noise = ["{", "}", "(", ")", "[", "]", ";", ",", "*", "=", "#", "#ifdef", "#endif",
                 "#else", "in", "out", "size=", "count=n", "struct", "union", "enum", "trusted",
                 "public", '"x.edl"', "import", "from", "void", "unsigned", "long", "0x1"]
        with tempfile.TemporaryDirectory() as d:
            edl = os.path.join(d, "main.edl")
            for _ in range(300):
                with open(rng.choice(files), errors="replace") as f:
                    toks = re.findall(r'"[^"\n]*"|\w+|\S', f.read())
                for _ in range(rng.randint(1, 6)):
                    i = rng.randrange(len(toks) + 1)
                    if rng.random() < 0.5 and toks:
                        del toks[min(i, len(toks) - 1)]
                    else:
                        toks.insert(i, rng.choice(noise))
                with open(edl, "w") as f:
                    f.write(" ".join(toks))
                try:
                    p = Program([edl], search_paths(edl))
                    E.render(p, E.model_rows(p))
                    E.lint(p)
                except EdlError:
                    pass

    @unittest.skipUnless(OEEDGER8R, "no oeedger8r (set OEEDGER8R)")
    def test_differential(self):
        """What oeedger8r accepts is accepted, with the enclave-side prototypes
        (ECALL implementations, OCALL proxies) that the models index into."""
        proto = re.compile(r"^[^\n;()]*?\b(\w+)\(([^;]*?)\);", re.M | re.S)
        accepted = 0
        for edl in corpus():
            with tempfile.TemporaryDirectory() as tmp:
                cmd = [OEEDGER8R, "--trusted", "--header-only", "--trusted-dir", tmp]
                for s in search_paths(edl):
                    cmd += ["--search-path", s]
                if subprocess.run(cmd + [edl], cwd=tmp, capture_output=True).returncode:
                    continue
                accepted += 1
                p = Program([edl], search_paths(edl))
                name = os.path.splitext(os.path.basename(edl))[0]
                with open(os.path.join(tmp, f"{name}_t.h")) as f:
                    header = {m[1]: m[2].strip() for m in proto.finditer(f.read())}
            for f in p.functions.values():
                params = header[f.name]
                names = [] if params in ("", "void") else [
                    re.findall(r"(\w+)\s*(?:\[[^\]]*\])*\s*$", x)[0] for x in params.split(",")]
                retval = ["_retval"] if not f.trusted and f.returns != E.VOID else []
                self.assertEqual(names, retval + [q.name for q in f.params], f"{edl}: {f.name}")
        self.assertGreater(accepted, 100)


if __name__ == "__main__":
    unittest.main()
