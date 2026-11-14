#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
"""Generate CodeQL data extensions (Models-as-Data) from Open Enclave EDL files.

The EDL is the enclave's trust-boundary specification. This tool parses it
into a typed AST with the grammar of oeedger8r (parser.cpp of oeedger8r-cpp,
the reference implementation), resolves imports, derives what every ECALL
and OCALL moves across the boundary from the marshalling code oeedger8r
generates, and writes CodeQL models:

  codeql/cpp-all sourceModel
      "remote"             every host-controlled value, so the standard
                           queries cover the enclave threat model
      "oe-ecall-input"     ECALL parameters and [in] data
      "oe-ocall-output"    OCALL return values and [out] data (Iago surface)
      "oe-host-pointer"    pointer values chosen by the host
  codeql/cpp-all sinkModel
      "oe-host-disclosure" data handed to the host by OCALLs
      "remote-sink"        the same data, for the standard queries
  openenclave/sgx-all oeEdlFunction / oeEdlParameter
      the EDL declarations themselves

Struct and union members are modeled one by one (`Field[...]` access paths
that follow oeedger8r's deep-copy rules), because CodeQL's C++ taint
tracking does not consider the members of a tainted object tainted.
With --lint, also reports risky EDL patterns.

The EDL files are expected to be accepted by oeedger8r: syntax and import
errors are reported, oeedger8r's checks of attribute combinations are not
repeated. Requires Python 3.10.

Example:
    edl2codeql.py --search-path ~/openenclave/include -D OE_SGX_ENTROPY \\
        --out models/cpp/ext/generated/oe-system-edl.model.yml \\
        ~/openenclave/include/openenclave/edl/core.edl \\
        ~/openenclave/include/openenclave/edl/sgx/platform.edl \\
        ~/openenclave/include/openenclave/edl/syscall.edl
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pprint
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, NamedTuple

# ---------------------------------------------------------------------------
# Tokens


class Loc(NamedTuple):
    path: str
    line: int
    column: int

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


class EdlError(Exception):
    def __init__(self, loc: Loc | None, message: str):
        super().__init__(f"{loc}: error: {message}" if loc else f"error: {message}")


class Token(NamedTuple):
    kind: str  # name, int, str, punct or eof
    text: str
    loc: Loc


# The lexical rules of oeedger8r: strings have no escapes.
_TOKEN = re.compile(r"""
    (?P<space>[\s\b]+ | //[^\n]* | /\*.*?\*/)
  | (?P<name>[A-Za-z_]\w*) | (?P<int>\d\w*) | (?P<str>"[^"\n]*") | (?P<punct>[{}()\[\]*,;=\#])
  | (?P<bad>/\*|"|.)""", re.VERBOSE | re.DOTALL | re.ASCII)


def tokenize(text: str, path: str) -> Iterator[Token]:
    line, bol = 1, 0
    for m in _TOKEN.finditer(text):
        kind, lexeme = m.lastgroup, m.group()
        loc = Loc(path, line, m.start() - bol + 1)
        if kind == "bad":
            raise EdlError(loc, {"/*": "unterminated comment", '"': "unterminated string"}
                           .get(lexeme, f"unexpected character {lexeme!r}"))
        if kind != "space":
            yield Token(kind, lexeme, loc)
        elif "\n" in lexeme:
            line += lexeme.count("\n")
            bol = m.start() + lexeme.rindex("\n") + 1
    yield Token("eof", "", Loc(path, line, len(text) - bol + 1))


def preprocess(tokens: Iterable[Token], defines: frozenset[str]) -> Iterator[Token]:
    """oeedger8r's conditionals: #ifdef, #ifndef, #else and #endif, which may
    appear between any two tokens."""
    stack: list[tuple[str, bool, Loc]] = []  # open conditionals: directive, taken, location
    tokens = iter(tokens)
    for t in tokens:
        if t.text == "#":
            d = next(tokens)
            if d.text in ("ifdef", "ifndef"):
                name = next(tokens)
                if name.kind != "name":
                    raise EdlError(name.loc, f"expected a macro name after #{d.text}")
                stack.append((d.text, (name.text in defines) == (d.text == "ifdef"), t.loc))
            elif d.text == "else" and stack and stack[-1][0] != "else":
                stack[-1] = ("else", not stack[-1][1], t.loc)
            elif d.text == "endif" and stack:
                stack.pop()
            elif d.text in ("else", "endif"):
                raise EdlError(d.loc, f"#{d.text} without #ifdef or #ifndef")
            else:
                raise EdlError(d.loc, f"unsupported directive #{d.text}: oeedger8r supports "
                                      "only #ifdef, #ifndef, #else and #endif")
        elif t.kind == "eof" and stack:
            raise EdlError(stack[-1][2], f"unterminated #{stack[-1][0]}")
        elif t.kind == "eof" or all(taken for _, taken, _ in stack):
            yield t


# ---------------------------------------------------------------------------
# Abstract syntax tree. Nodes are immutable; equality ignores locations.


def _loc():
    return field(default=None, compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class Type:
    """`[const] name *...`: an EDL type is a base type and pointers to it."""

    name: str  # e.g. "unsigned long", "size_t", a struct or a foreign typedef
    tag: str = ""  # "struct", "union" or "enum" when spelled out
    const: bool = False
    ptr: int = 0

    def deref(self) -> Type:
        return dataclasses.replace(self, ptr=self.ptr - 1)

    def __str__(self) -> str:
        tag = f"{self.tag} " if self.tag else ""
        return f"{'const ' if self.const else ''}{tag}{self.name}{'*' * self.ptr}"


VOID = Type("void")
FLAGS = ("in", "out", "string", "wstring", "isptr", "isary", "user_check")
ATTRIBUTES = (*FLAGS, "size", "count")


@dataclass(frozen=True, slots=True)
class Decl:
    """A parameter or a member: `[attributes] type name[dims]`."""

    name: str
    type: Type
    attrs: frozenset[str] = frozenset()  # the FLAGS that are present
    size: int | str | None = None  # size= and count=: a literal or a sibling's name
    count: int | str | None = None
    dims: tuple[int | str, ...] = ()
    loc: Loc | None = _loc()

    @property
    def pointer_like(self) -> bool:
        """Passed by address: a pointer, an array or an isptr/isary type."""
        return bool(self.type.ptr or self.dims or self.attrs & {"isptr", "isary"})

    @property
    def annotated(self) -> bool:
        return bool(self.attrs) or self.size is not None or self.count is not None

    @property
    def c_type(self) -> str:
        return str(self.type) + "".join(f"[{d}]" for d in self.dims)

    @property
    def attributes(self) -> str:
        values = (f"{k}={v}" for k, v in (("size", self.size), ("count", self.count))
                  if v is not None)
        return ",".join([*(a for a in FLAGS if a in self.attrs), *values])


@dataclass(frozen=True, slots=True)
class Function:
    name: str
    returns: Type
    params: tuple[Decl, ...]
    trusted: bool  # an ECALL; untrusted functions are OCALLs
    allow: tuple[str, ...] | None = None
    switchless: bool = False  # transition_using_threads
    propagate_errno: bool = False
    loc: Loc | None = _loc()

    @property
    def flags(self) -> str:
        return ",".join(name for name, on in (
            ("public", self.trusted), ("allow", self.allow is not None),
            ("transition_using_threads", self.switchless),
            ("propagate_errno", self.propagate_errno)) if on)


@dataclass(frozen=True, slots=True)
class Struct:
    kind: str  # "struct" or "union"
    name: str
    members: tuple[Decl, ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True, slots=True)
class Enum:
    name: str | None
    members: tuple[str, ...]
    loc: Loc | None = _loc()


@dataclass(frozen=True, slots=True)
class Import:
    path: str
    names: tuple[str, ...] | None  # None: every function (`import "f"`, `from "f" import *`)
    loc: Loc | None = _loc()


@dataclass(frozen=True, slots=True)
class Include:
    header: str
    loc: Loc | None = _loc()


@dataclass(frozen=True, slots=True)
class Edl:
    path: str
    items: tuple[Include | Import | Enum | Struct | Function, ...]  # sections are flattened


# ---------------------------------------------------------------------------
# Parser: recursive descent over the productions of oeedger8r's parser.cpp,
# which is the reference where it differs from its docs/Grammar.md.


def _describe(t: Token) -> str:
    return "end of file" if t.kind == "eof" else f"'{t.text}'"


class Parser:
    def __init__(self, tokens: Iterable[Token]):
        self.toks = list(tokens)
        self.i = 0

    def peek(self, k: int = 0) -> Token:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self) -> Token:
        t = self.peek()
        if t.kind != "eof":
            self.i += 1
        return t

    def accept(self, text: str) -> bool:
        if self.peek().text != text:
            return False
        self.next()
        return True

    def expect(self, text: str, context: str = "") -> None:
        t = self.next()
        if t.text != text:
            raise EdlError(t.loc, f"expected '{text}'{context}, got {_describe(t)}")

    def token(self, kind: str, what: str) -> Token:
        t = self.next()
        if t.kind != kind:
            raise EdlError(t.loc, f"expected {what}, got {_describe(t)}")
        return t

    def value(self, what: str) -> int | str:
        t = self.next()
        if t.kind not in ("int", "name"):
            raise EdlError(t.loc, f"expected {what} (an integer or a name), got {_describe(t)}")
        if t.kind == "int" and not t.text.isdigit():
            raise EdlError(t.loc, f"invalid integer '{t.text}': EDL integers are decimal")
        return int(t.text) if t.kind == "int" else t.text

    def sequence(self, item: Callable, close: str, sep: str = ",") -> tuple:
        """`[item (sep item)* [sep]] close`, the list syntax that oeedger8r accepts."""
        items = []
        while not self.accept(close):
            items.append(item())
            if self.peek().text != close:
                self.expect(sep)
        return tuple(items)

    def names(self, close: str) -> tuple[str, ...]:
        return self.sequence(lambda: self.token("name", "a function name").text, close)

    # edl := "enclave" "{" item* "}"; what follows is ignored, as by oeedger8r.
    def edl(self, path: str) -> Edl:
        self.expect("enclave", " at the start of the file")
        self.expect("{")
        items = []
        while not self.accept("}"):
            items += self.item()
        return Edl(path, tuple(items))

    def item(self) -> Iterator[Include | Import | Enum | Struct | Function]:
        t = self.next()
        match t.text:
            case "trusted" | "untrusted":
                self.expect("{")
                while not self.accept("}"):
                    yield self.function(t.text == "trusted")
                self.expect(";")
            case "include":
                yield Include(self.token("str", "a header name").text[1:-1], t.loc)
            case "import":
                yield Import(self.token("str", "an EDL file name").text[1:-1], None, t.loc)
            case "from":
                path = self.token("str", "an EDL file name").text[1:-1]
                self.expect("import")
                if self.accept("*"):
                    self.expect(";")
                    yield Import(path, None, t.loc)
                else:
                    yield Import(path, self.names(";"), t.loc)
            case "enum":
                name = self.next().text if self.peek().kind == "name" else None
                self.expect("{")
                members = self.sequence(self.enumerator, "}")
                self.expect(";")
                yield Enum(name, members, t.loc)
            case "struct" | "union":
                name = self.token("name", f"a {t.text} name")
                self.expect("{")
                allowed = ("size", "count") if t.text == "struct" else ()
                members = self.sequence(lambda: self.decl(allowed), "}", ";")
                self.expect(";")
                yield Struct(t.text, name.text, members, name.loc)
            case _:
                raise EdlError(t.loc, f"unexpected {_describe(t)}: expected trusted, untrusted, "
                                      "include, import, from, enum, struct or union")

    def enumerator(self) -> str:
        name = self.token("name", "an enumerator").text
        if self.accept("="):
            self.value("an enumerator value")
        return name

    def function(self, trusted: bool) -> Function:
        if trusted and not self.accept("public"):
            raise EdlError(self.peek().loc, "trusted functions must be 'public' (oeedger8r "
                                            "does not support 'private')")
        returns = self.type()
        name = self.token("name", "a function name")
        self.expect("(")
        if self.peek().text == "void" and self.peek(1).text == ")":
            self.next()
        params = self.sequence(self.decl, ")")
        allow = None
        if self.accept("allow"):
            if trusted:
                raise EdlError(name.loc, "'allow' is invalid for trusted functions (ECALLs)")
            self.expect("(")
            allow = self.names(")")
        switchless = errno = False
        for _ in range(2):  # in either order
            if not switchless and self.accept("transition_using_threads"):
                switchless = True
            elif not trusted and not errno and self.accept("propagate_errno"):
                errno = True
        self.expect(";", f" after the declaration of '{name.text}'")
        return Function(name.text, returns, params, trusted, allow, switchless, errno, name.loc)

    def decl(self, allowed: tuple[str, ...] = ATTRIBUTES) -> Decl:
        attrs = self.attributes(allowed) if self.peek().text == "[" else {}
        type_ = self.type()
        name = self.token("name", "a name")
        dims = []
        while self.accept("["):
            dims.append(self.value("an array dimension"))
            self.expect("]")
        return Decl(name.text, type_, frozenset(attrs.keys() - {"size", "count"}),
                    attrs.get("size"), attrs.get("count"), tuple(dims), name.loc)

    def attributes(self, allowed: tuple[str, ...]) -> dict[str, int | str | None]:
        start = self.next()
        attrs: dict[str, int | str | None] = {}

        def attribute():
            t = self.token("name", "an attribute")
            if t.text in attrs:
                raise EdlError(t.loc, f"duplicated attribute '{t.text}'")
            if t.text not in allowed:
                raise EdlError(t.loc, f"attribute '{t.text}' is not allowed here"
                               if t.text in ATTRIBUTES else f"unknown attribute '{t.text}'")
            attrs[t.text] = None
            if t.text in ("size", "count"):
                self.expect("=", f" after '{t.text}'")
                attrs[t.text] = self.value(f"a {t.text}")

        if not self.sequence(attribute, "]"):
            raise EdlError(start.loc, "empty attribute list")
        return attrs

    # type := ["const"] (integer-type | ("struct"|"union"|"enum") name | name) "*"*
    def type(self) -> Type:
        const = self.accept("const")
        t = self.next()
        tag = t.text if t.text in ("struct", "union", "enum") else ""
        name = self.token("name", f"a {tag} name").text if tag else self.base_type(t)
        ptr = 0
        while self.accept("*"):
            ptr += 1
        return Type(name, tag, const, ptr)

    def base_type(self, t: Token) -> str:
        """oeedger8r's integer types (`long long int` is not one), or a type name."""
        unsigned = t.text == "unsigned" and self.peek().text in ("char", "short", "int", "long")
        if unsigned:
            t = self.next()
        elif t.text == "unsigned":
            return "unsigned int"
        name = t.text
        if name == "long" and self.peek().text in ("int", "long", "double"):
            name = {"int": "long", "long": "long long", "double": "long double"}[self.next().text]
        elif name in ("short", "char"):
            self.accept("int")
        elif t.kind != "name":
            raise EdlError(t.loc, f"expected a type, got {_describe(t)}")
        if unsigned and name == "long double":
            raise EdlError(t.loc, "'unsigned long double' is not a type")
        return f"unsigned {name}" if unsigned else name


def parse(text: str, path: str, defines: frozenset[str] = frozenset()) -> Edl:
    return Parser(preprocess(tokenize(text, path), defines)).edl(path)


# ---------------------------------------------------------------------------
# Imports, with oeedger8r's semantics: the interface of an EDL is its own
# functions and the ones it imports; `import "f"` and `from "f" import *`
# import every function of f, `from "f" import a, b` the listed ones; types
# are always imported. Each file is parsed once.


@dataclass(eq=False)
class Module:
    edl: Edl
    name: str  # stable name: relative to the search path the file was found in
    types: dict[str, Struct | Enum] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)


def _define(table: dict, node: Struct | Enum | Function) -> None:
    previous = table.setdefault(node.name, node)
    if previous is not node:
        raise EdlError(node.loc, f"duplicate definition of '{node.name}' (the other one is "
                                 f"at {previous.loc})")


def _relative(path: str, *bases: str) -> str:
    for base in bases:
        rel = os.path.relpath(path, base)
        if not rel.startswith(os.pardir):
            return rel.replace(os.sep, "/")
    return path


class Program:
    """The root EDL files, everything they import, and their union."""

    def __init__(self, roots: Iterable[str], search_paths: Iterable[str] = (),
                 defines: Iterable[str] = ()):
        self.search_paths = [os.path.abspath(p) for p in search_paths]
        self.defines = frozenset(defines)
        self.modules: dict[str, Module] = {}  # by real path
        self.types: dict[str, Struct | Enum] = {}
        self.functions: dict[str, Function] = {}
        self._loading: list[str] = []
        for root in roots:
            module = self.load(root, None, None)
            for t in module.types.values():
                _define(self.types, t)
            for f in module.functions.values():
                _define(self.functions, f)

    def resolve(self, spec: str, importer: str | None) -> str | None:
        """oeedger8r tries the working directory, then the search paths; then the
        importer's directory and <search path>/openenclave/edl[/sgx], where the
        system EDLs live, are tried."""
        dirs = [os.getcwd(), *self.search_paths]
        if importer:
            dirs.append(os.path.dirname(importer))
        for d in self.search_paths:
            dirs += [os.path.join(d, "openenclave", "edl"),
                     os.path.join(d, "openenclave", "edl", "sgx")]
        for d in dirs:
            path = os.path.join(d, spec)
            if os.path.isfile(path):
                return os.path.abspath(path)
        return None

    def load(self, spec: str, importer: str | None, loc: Loc | None) -> Module:
        path = self.resolve(spec, importer)
        if path is None:
            raise EdlError(loc, f"cannot find EDL file '{spec}'"
                                + ("" if self.search_paths else " (no --search-path given)"))
        key = os.path.realpath(path)
        if key in self._loading:
            cycle = [*self._loading[self._loading.index(key):], key]
            raise EdlError(loc, "recursive import: " + " -> ".join(map(os.path.basename, cycle)))
        if key in self.modules:
            return self.modules[key]
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            raise EdlError(loc, f"cannot read {path}: {e.strerror}") from None
        edl = parse(text, _relative(path, os.getcwd()), self.defines)
        module = Module(edl, _relative(path, *self.search_paths, os.getcwd()))
        self._loading.append(key)
        for item in edl.items:
            match item:
                case Import():
                    imported = self.load(item.path, path, item.loc)
                    for t in imported.types.values():
                        _define(module.types, t)
                    for name in imported.functions if item.names is None else item.names:
                        if name not in imported.functions:
                            raise EdlError(item.loc, f"function '{name}' not found in "
                                                     f"'{item.path}'")
                        _define(module.functions, imported.functions[name])
                case Struct() | Enum(name=str()):
                    _define(module.types, item)
                case Function():
                    _define(module.functions, item)
        self._loading.pop()
        self.modules[key] = module
        return module


# ---------------------------------------------------------------------------
# The trust boundary: what each function moves between host and enclave, as
# (access path, kinds) pairs. The rules are those of the code oeedger8r
# generates (f_emitter.h, w_emitter.h).
#
# ECALLs run the implementation `R f(P0, ..., Pn)` in the enclave:
#   - by-value parameters are host data;
#   - [in] and [in,out] buffers are copied in: their contents are host data.
#     Struct members with size or count are deep-copied (what they point to
#     is host data); other pointer members keep the host's value;
#   - [out] buffers are fresh enclave memory;
#   - [user_check] and unannotated pointers, arrays and isptr/isary values are
#     passed through: they are pointers chosen by the host.
# The return value goes to the host, which sink models cannot express.
#
# OCALLs are called through the proxy `oe_result_t f([R* _retval,] P0, ..., Pn)`:
#   - *_retval and [out]/[in,out] buffers receive host data, with the same
#     deep-copy rules;
#   - by-value parameters, [in]/[in,out] buffer contents and the value of
#     [user_check] or unannotated pointers are handed to the host.

ECALL_INPUT = ("remote", "oe-ecall-input")
OCALL_OUTPUT = ("remote", "oe-ocall-output")
HOST_POINTER = ("oe-host-pointer",)
HOST_MEMORY = ("remote",)
DISCLOSED = ("oe-host-disclosure", "remote-sink")
MAX_DEPTH = 4  # of nested struct expansion


class Path(tuple):
    """A Models-as-Data access path as (token, argument, indirection) steps:
    Path.root("Argument", 1).deref().field("S", "buf").deref() is
    `Argument[*1].Field[*S::buf]`."""

    @staticmethod
    def root(token: str, index: int, indirection: int = 0) -> Path:
        return Path([(token, index, indirection)])

    def deref(self) -> Path:
        *init, (token, arg, n) = self
        return Path([*init, (token, arg, n + 1)])

    def field(self, struct: str, member: str) -> Path:
        return Path([*self, ("Field", f"{struct}::{member}", 0)])

    def __str__(self) -> str:
        return ".".join(f"{token}[{'*' * n}{arg}]" for token, arg, n in self)


def _element(p: Decl) -> Type | None:
    """The type of what a pointer-like parameter points to, if known."""
    if p.dims:
        return None if "isary" in p.attrs else p.type
    return p.type.deref() if p.type.ptr else None


def _host_pointer(path: Path) -> Iterator[tuple[Path, tuple[str, ...]]]:
    yield path, HOST_POINTER
    yield path.deref(), HOST_MEMORY


class Boundary:
    def __init__(self, types: dict[str, Struct | Enum]):
        self.types = types

    def aggregate(self, t: Type | None) -> Struct | None:
        """The EDL struct or union that `t` is (`S` and `struct S` both name S)."""
        s = self.types.get(t.name) if t is not None and not t.ptr and t.tag != "enum" else None
        return s if isinstance(s, Struct) and t.tag in ("", s.kind) else None

    @staticmethod
    def deep_copied(s: Struct) -> set[str]:
        """Struct members that oeedger8r deep-copies: the annotated ones that are
        not the size or count of another member."""
        if s.kind != "struct":
            return set()
        sizes = {v for m in s.members for v in (m.size, m.count) if isinstance(v, str)}
        return {m.name for m in s.members if m.annotated and m.name not in sizes}

    def deep(self, p: Decl) -> bool:
        """Holds if the struct that `p` points to is deep-copied."""
        s = self.aggregate(p.type.deref()) if p.type.ptr == 1 and p.annotated else None
        return s is not None and bool(self.deep_copied(s))

    def crossings(self, f: Function) -> Iterator[tuple[Path, tuple[str, ...]]]:
        if f.trusted:
            for i, p in enumerate(f.params):
                root = Path.root("Parameter", i)
                if "user_check" in p.attrs or (p.pointer_like and not p.attrs & {"in", "out"}):
                    yield from _host_pointer(root)
                elif not p.pointer_like:
                    yield from self.data(root, p.type, ECALL_INPUT)
                elif "in" in p.attrs:
                    yield from self.data(root.deref(), _element(p), ECALL_INPUT, self.deep(p))
            return
        shift = 0 if f.returns == VOID else 1
        if shift:
            yield from self.data(Path.root("Argument", 0, 1), f.returns, OCALL_OUTPUT)
        for i, p in enumerate(f.params, shift):
            root = Path.root("Argument", i)
            if not p.pointer_like:
                yield from self.data(root, p.type, DISCLOSED)
            elif "user_check" in p.attrs or not p.attrs & {"in", "out"}:
                yield root, DISCLOSED
            else:
                for direction, kinds in (("in", DISCLOSED), ("out", OCALL_OUTPUT)):
                    if direction in p.attrs:
                        yield from self.data(root.deref(), _element(p), kinds, self.deep(p))

    def data(self, path: Path, t: Type | None, kinds: tuple[str, ...], deep: bool = False,
             seen: tuple[str, ...] = ()) -> Iterator[tuple[Path, tuple[str, ...]]]:
        """Data of type `t` (None if unknown) that is copied across the boundary to `path`."""
        yield path, kinds
        inbound = kinds != DISCLOSED
        if inbound and t is not None and t.ptr:
            yield from _host_pointer(path)
        s = self.aggregate(t)
        if s is None or s.name in seen or len(seen) >= MAX_DEPTH:
            return
        copied = self.deep_copied(s) if deep else set()
        for m in s.members:
            member = path.field(s.name, m.name)
            pointer = m.type.ptr and not m.dims
            if pointer and m.name in copied:
                yield from self.data(member.deref(), m.type.deref(), kinds, deep, (*seen, s.name))
            elif pointer and inbound:
                yield from _host_pointer(member)
            elif m.type.ptr or m.dims:
                yield member, kinds
            else:
                yield from self.data(member, m.type, kinds, False, (*seen, s.name))


# ---------------------------------------------------------------------------
# CodeQL models


def model_rows(program: Program) -> list[tuple[str, str, str, str]]:
    """(extensible, function, access path, kind) rows, by function name."""
    boundary = Boundary(program.types)
    rows: dict[tuple[str, str, str, str], None] = {}
    for f in sorted(program.functions.values(), key=lambda f: f.name):
        for path, kinds in boundary.crossings(f):
            table = "sinkModel" if kinds == DISCLOSED else "sourceModel"
            rows.update(dict.fromkeys((table, f.name, str(path), kind) for kind in kinds))
    return list(rows)


def _yaml(value: object) -> str:
    """A YAML flow scalar (JSON string escapes are valid in YAML)."""
    return str(value) if isinstance(value, int) else json.dumps(value)


def render(program: Program, rows: list[tuple[str, str, str, str]],
           pack: str = "openenclave/sgx-all") -> str:
    functions = sorted(program.functions.values(), key=lambda f: f.name)
    mad = "namespace, type, subtypes, name, signature, ext, {}, kind, provenance"
    tables = [("codeql/cpp-all", table, mad.format(column),
               [["", "", False, f, "", "", path, kind, "manual"]
                for t, f, path, kind in rows if t == table])
              for table, column in (("sourceModel", "output"), ("sinkModel", "input"))]
    tables += [
        (pack, "oeEdlFunction", "name, side (trusted|untrusted), return type, flags",
         [[f.name, "trusted" if f.trusted else "untrusted", str(f.returns), f.flags]
          for f in functions]),
        (pack, "oeEdlParameter", "function, EDL parameter index, name, type, attributes",
         [[f.name, i, p.name, p.c_type, p.attributes]
          for f in functions for i, p in enumerate(f.params)]),
    ]
    out = ["# Generated by edl2codeql.py from the EDL files below. Do not edit.",
           "# Defines: " + (" ".join(f"-D{d}" for d in sorted(program.defines)) or "none"),
           "# Sources:", *sorted(f"#   {m.name}" for m in program.modules.values()),
           "extensions:"]
    for table_pack, extensible, columns, data in tables:
        out += ["  - addsTo:", f"      pack: {table_pack}", f"      extensible: {extensible}",
                f"    data:{'' if data else ' []'} # {columns}"]
        out += [f"      - [{', '.join(map(_yaml, row))}]" for row in data]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Lint

_READ_LIKE = re.compile(r"read|recv|get|query", re.I)
_SIGNED = {"char", "short", "int", "long", "long long", "int8_t", "int16_t", "int32_t",
           "int64_t", "ssize_t"}
_SIZES = {  # LP64, with typedefs that EDL files use without defining them
    **dict.fromkeys(["char", "unsigned char", "bool", "int8_t", "uint8_t"], 1),
    **dict.fromkeys(["short", "unsigned short", "int16_t", "uint16_t", "oe_sa_family_t",
                     "sa_family_t", "oe_in_port_t", "in_port_t"], 2),
    **dict.fromkeys(["int", "unsigned int", "int32_t", "uint32_t", "float", "wchar_t",
                     "oe_result_t", "oe_socklen_t", "socklen_t", "oe_pid_t", "pid_t",
                     "oe_uid_t", "uid_t", "oe_gid_t", "gid_t", "oe_mode_t", "mode_t"], 4),
    **dict.fromkeys(["long", "unsigned long", "long long", "unsigned long long", "int64_t",
                     "uint64_t", "size_t", "ssize_t", "double", "oe_host_fd_t", "oe_off_t",
                     "off_t", "time_t"], 8),
    "long double": 16,
}


def _size(t: Type, types: dict[str, Struct | Enum]) -> int | None:
    if t.ptr or t.tag in ("struct", "union"):
        return None
    return 4 if t.tag == "enum" or isinstance(types.get(t.name), Enum) else _SIZES.get(t.name)


def lint(program: Program) -> list[tuple[Loc, str, str]]:
    """Risky EDL patterns, as (location, rule, message) sorted by location."""
    boundary = Boundary(program.types)
    findings: dict[tuple[str, str, str], tuple[Loc, str, str]] = {}
    for f in program.functions.values():
        side = "ecall" if f.trusted else "ocall"
        shift = 0 if f.trusted or f.returns == VOID else 1

        def report(rule: str, p: Decl | None, subject: str, message: str) -> None:
            findings.setdefault((rule, f.name, subject),
                                ((p or f).loc, rule, f"{side.upper()} '{f.name}': {message}"))

        for path, kinds in boundary.crossings(f):
            if kinds != HOST_POINTER:
                continue
            (_, index, stars), whole = path[0], len(path) == 1
            p = f.params[index - shift] if index >= shift else None
            if f.trusted and whole and not stars:
                user_check = "user_check" in p.attrs
                report("ecall-user-check" if user_check else "ecall-unannotated-pointer", p,
                       p.name, f"'{p.name}' is a pointer chosen by the host"
                       + ("" if user_check else " (the parameter has no direction)")
                       + "; check it with oe_is_outside_enclave and copy the data in before use")
            elif p is None and whole:
                report("ocall-returns-pointer", None, str(path), "the returned pointer is "
                       "chosen by the host; check it with oe_is_outside_enclave before use")
            else:
                report(f"{side}-embedded-host-pointer", p, str(path), f"{path} is a pointer "
                       "chosen by the host; check it with oe_is_outside_enclave before use")
        if f.trusted and f.returns.ptr:
            report("ecall-returns-pointer", None, "", "returning a pointer discloses an enclave "
                   "address to the host")
        for p in f.params:
            if not f.trusted and {"in", "out"} <= p.attrs and _READ_LIKE.search(f.name):
                report("ocall-inout-read", p, p.name, f"[in,out] on '{p.name}' copies the "
                       "buffer's previous contents to the host (cf. CVE-2020-15224); use [out]")
            size = _size(p.type.deref(), program.types) if p.type.ptr else None
            if isinstance(p.size, int) and p.count is None and size and p.size < size:
                report("size-smaller-than-type", p, p.name, f"size={p.size} but "
                       f"sizeof({p.type.deref()}) is {size}: only {p.size} byte(s) of "
                       f"'{p.name}' are copied")
            for key, ref in (("size", p.size), ("count", p.count)):
                target = next((q for q in f.params if q.name == ref), None)
                if target and not target.pointer_like and target.type.name in _SIGNED:
                    report("signed-size", p, f"{p.name}.{key}", f"'{p.name}' has {key}={ref}, "
                           f"which is a signed '{target.type}'")
    return sorted(findings.values())


# ---------------------------------------------------------------------------
# Command line


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("edl", nargs="+", help="root EDL files")
    ap.add_argument("--search-path", action="append", default=[], metavar="DIR",
                    help="directory searched for EDL files (repeatable), as for oeedger8r")
    ap.add_argument("-D", dest="defines", action="append", default=[], metavar="NAME",
                    help="define NAME for #ifdef and #ifndef, as for oeedger8r")
    ap.add_argument("--out", metavar="FILE", help="output .model.yml (default: stdout)")
    ap.add_argument("--check", action="store_true",
                    help="do not write --out FILE; exit with 1 if it is out of date")
    ap.add_argument("--pack", default="openenclave/sgx-all",
                    help="pack declaring oeEdlFunction and oeEdlParameter")
    ap.add_argument("--lint", action="store_true", help="report risky EDL patterns")
    ap.add_argument("--dump-ast", action="store_true", help="print the AST of every EDL file")
    args = ap.parse_args(argv)
    if args.check and args.out in (None, "-"):
        ap.error("--check requires --out FILE")
    try:
        program = Program(args.edl, args.search_path, args.defines)
    except EdlError as e:
        print(e, file=sys.stderr)
        return 1

    status = 0
    if args.dump_ast:
        pprint.pprint({m.name: m.edl for m in program.modules.values()}, width=120,
                      sort_dicts=False)
    if args.out or not (args.lint or args.dump_ast):
        rows = model_rows(program)
        text = render(program, rows, args.pack)
        if args.check:
            try:
                with open(args.out, encoding="utf-8") as f:
                    status = int(f.read() != text)
            except FileNotFoundError:
                status = 1
            print(f"{args.out} is {'out of date' if status else 'up to date'}", file=sys.stderr)
        elif args.out in (None, "-"):
            sys.stdout.write(text)
        else:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            sources = sum(r[0] == "sourceModel" for r in rows)
            print(f"wrote {args.out} ({len(program.functions)} functions, {sources} source "
                  f"rows, {len(rows) - sources} sink rows)", file=sys.stderr)
    if args.lint:
        for loc, rule, message in lint(program):
            print(f"{loc}: warning: {message} [{rule}]")
    return status


if __name__ == "__main__":
    sys.exit(main())
