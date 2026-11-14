#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
"""Build a CodeQL C/C++ database of the Open Enclave SDK without CMake.

The OE core libraries only generate oeedger8r *headers*. The ECALL/OCALL
stubs that implement the host/enclave boundary are generated into every
enclave application, so a database built from the OE CMake project alone
contains no stub bodies. This script:

  1. builds oeedger8r from <oe-src>/tools/oeedger8r-cpp,
  2. stages every header the OE build normally generates (edger8r
     headers, EDL structure headers, musl headers, mbedTLS config),
  3. generates *full* trusted stubs for an enclave that imports all
     system EDLs (exactly what an OE application compiles), and
  4. traces compile-only invocations of the enclave, syscall, common and
     host sources plus the generated stubs under `codeql database create`.

Example:
    build_oe_codeql_db.py --oe-src ~/openenclave \
        --codeql build/codeql-cli/codeql/codeql --db build/oe-db
"""
import argparse
import concurrent.futures
import json
import os
import shlex
import shutil
import subprocess
import sys

SYSTEM_EDLS = [
    "openenclave/edl/core.edl",
    "openenclave/edl/sgx/platform.edl",
    "openenclave/edl/syscall.edl",
]

# EDL files whose structure definitions OE publishes as headers
# (see host/CMakeLists.txt: EDL_PUBLIC/PRIVATE_STRUCTURES).
EDL_STRUCT_HEADERS = {
    "openenclave/bits": ["asym_keys.edl", "time.edl"],
    "openenclave/internal/bits": [
        "fcntl.edl", "poll.edl", "socket.edl", "utsname.edl"],
    "openenclave/internal/bits/sgx": ["sgx/switchless.edl"],
}

SYSCALL_DIRS = ["syscall"]
COMMON_DIRS = ["common", "common/sgx", "common/tdx"]
HOST_DIRS = [
    "host", "host/sgx", "host/sgx/linux", "host/sgx/ocalls", "host/linux",
    "host/ocalls", "host/crypto", "host/crypto/openssl", "host/tdx",
    "common/crypto/openssl"]


def run(cmd, **kw):
    print("+ " + " ".join(shlex.quote(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def c_files(src, rel_dirs, recursive=False):
    out = []
    for rel in rel_dirs:
        base = os.path.join(src, rel)
        if not os.path.isdir(base):
            continue
        if recursive:
            for root, _, files in os.walk(base):
                out += [os.path.join(root, f) for f in files if f.endswith(".c")]
        else:
            out += [os.path.join(base, f) for f in sorted(os.listdir(base))
                    if f.endswith(".c")]
    return out


def build_edger8r(src, work):
    exe = os.path.join(work, "bin", "oeedger8r")
    if os.path.exists(exe):
        return exe
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    edger8r_src = os.path.join(src, "tools", "oeedger8r-cpp", "src")
    run(["g++", "-std=c++17", "-O1", "-o", exe] +
        [os.path.join(edger8r_src, f) for f in ("lexer.cpp", "parser.cpp", "main.cpp")])
    return exe


def edger8r(exe, src, edl, mode, out_dir, header_only=True, defines=()):
    os.makedirs(out_dir, exist_ok=True)
    cmd = [exe, "--search-path", os.path.join(src, "include"),
           "--search-path", os.path.join(src, "include", "openenclave", "edl"),
           "--search-path", os.path.join(src, "include", "openenclave", "edl", "sgx")]
    if header_only:
        cmd.append("--header-only")
    cmd += ["--" + mode, "--%s-dir" % mode, out_dir]
    cmd += ["-D" + d for d in defines]
    cmd.append(edl)
    run(cmd)


def stage_musl(src, stage_inc):
    musl = os.path.join(src, "3rdparty", "musl", "musl")
    patches = os.path.join(src, "3rdparty", "musl", "patches")
    libc = os.path.join(stage_inc, "openenclave", "libc")
    if os.path.isdir(libc):
        return
    shutil.copytree(os.path.join(musl, "include"), libc)
    bits = os.path.join(libc, "bits")
    for arch_bits in ("arch/generic/bits", "arch/x86_64/bits"):
        shutil.copytree(os.path.join(musl, arch_bits), bits, dirs_exist_ok=True)
    with open(os.path.join(bits, "alltypes.h"), "w") as f:
        subprocess.run(["sed", "-f", os.path.join(musl, "tools", "mkalltypes.sed"),
                        os.path.join(musl, "arch", "x86_64", "bits", "alltypes.h.in"),
                        os.path.join(musl, "include", "alltypes.h.in")],
                       stdout=f, check=True)
    syscall_in = os.path.join(musl, "arch", "x86_64", "bits", "syscall.h.in")
    with open(os.path.join(bits, "syscall.h"), "w") as f:
        f.write(open(syscall_in).read())
        f.write(subprocess.run(["sed", "-n", "-e", "s/__NR_/SYS_/p", syscall_in],
                               capture_output=True, text=True, check=True).stdout)
    shutil.copy(os.path.join(libc, "endian.h"), os.path.join(libc, "__endian.h"))
    for hdr in ("endian.h", "setjmp.h", "execinfo.h"):
        shutil.copy(os.path.join(patches, hdr), os.path.join(libc, hdr))
    shutil.copy(os.path.join(src, "3rdparty", "musl", "deprecations.h"),
                os.path.join(bits, "deprecations.h"))


def stage_mbedtls_config(src, stage):
    out_dir = os.path.join(stage, "mbedtls")
    os.makedirs(out_dir, exist_ok=True)
    lines = []
    for line in open(os.path.join(src, "3rdparty", "mbedtls", "config.h")):
        if line.startswith("#cmakedefine"):
            line = "/* #undef %s */\n" % line.split()[1]
        lines.append(line)
    open(os.path.join(out_dir, "config.h"), "w").writelines(lines)
    return out_dir


def write_aggregate_edl(work):
    path = os.path.join(work, "oe_sysedl.edl")
    with open(path, "w") as f:
        f.write("enclave {\n")
        for edl in SYSTEM_EDLS:
            f.write('    from "%s" import *;\n' % edl)
        f.write("};\n")
    return path


def generate(src, work):
    exe = build_edger8r(src, work)
    gen = os.path.join(work, "gen")
    stage_inc = os.path.join(work, "include")
    inc = os.path.join(src, "include")
    edger8r(exe, src, os.path.join(inc, "openenclave/edl/core.edl"), "trusted",
            os.path.join(gen, "core"))
    edger8r(exe, src, os.path.join(inc, "openenclave/edl/sgx/platform.edl"),
            "trusted", os.path.join(gen, "core"), defines=["OE_SGX_ENTROPY"])
    edger8r(exe, src, os.path.join(inc, "openenclave/edl/syscall.edl"), "trusted",
            os.path.join(gen, "syscall"))
    for edl in ("core.edl", "sgx/platform.edl", "syscall.edl"):
        edger8r(exe, src, os.path.join(inc, "openenclave/edl", edl), "untrusted",
                os.path.join(gen, "host"))
    for out_rel, edls in EDL_STRUCT_HEADERS.items():
        out_dir = os.path.join(stage_inc, out_rel)
        os.makedirs(out_dir, exist_ok=True)
        tmp = os.path.join(work, "gen", "structs")
        for edl in edls:
            edger8r(exe, src, os.path.join(inc, "openenclave/edl", edl), "untrusted", tmp)
            name = os.path.splitext(os.path.basename(edl))[0]
            shutil.copy(os.path.join(tmp, name + "_args.h"),
                        os.path.join(out_dir, name + ".h"))
    # Full trusted stubs (ECALL dispatchers + OCALL proxies) for all system EDLs.
    edger8r(exe, src, write_aggregate_edl(work), "trusted",
            os.path.join(gen, "sysedl"), header_only=False, defines=["OE_SGX_ENTROPY"])
    stage_musl(src, stage_inc)
    return gen, stage_inc, stage_mbedtls_config(src, work)


def compile_commands(src, work, gen, stage_inc, mbedtls_cfg, with_host):
    inc = os.path.join(src, "include")
    common = ["gcc", "-c", "-o", "/dev/null", "-w", "-std=gnu11", "-m64",
              "-DOE_API_VERSION=2"]
    enclave = common + ["-fPIE", "-nostdinc", "-fno-builtin", "-DOE_BUILD_ENCLAVE",
                        "-DOE_WITH_EXPERIMENTAL_EEID"]
    musl = ["-I" + os.path.join(stage_inc, "openenclave", "libc")]
    mbedtls = ["-DMBEDTLS_CONFIG_FILE=<config.h>",
               "-I" + os.path.join(src, "3rdparty", "mbedtls", "mbedtls", "include"),
               "-I" + mbedtls_cfg]
    core = ["-I" + os.path.join(gen, "core"), "-I" + inc, "-I" + stage_inc]
    sgx_private = ["-I" + os.path.join(src, "enclave", "core", "sgx"),
                   "-I" + os.path.join(src, "enclave", "sgx")]

    cmds = []
    # A few core files compile musl sources and need its headers last.
    for f in c_files(src, ["enclave/core", "enclave/core/sgx"]):
        cmds.append(enclave + core + musl + [f])
    for f in c_files(src, ["enclave", "enclave/sgx", "enclave/sealing/sgx",
                           "enclave/crypto/mbedtls"]) + c_files(src, COMMON_DIRS):
        cmds.append(enclave + mbedtls + core + sgx_private + musl + [f])
    syscall = ["-I" + os.path.join(gen, "syscall"),
               "-I" + os.path.join(inc, "openenclave", "corelibc"),
               "-I" + inc, "-I" + stage_inc]
    for f in c_files(src, SYSCALL_DIRS, recursive=True):
        cmds.append(enclave + syscall + musl + [f])
    sysedl = os.path.join(gen, "sysedl")
    for f in c_files(work, ["gen/sysedl"]):
        cmds.append(enclave + ["-I" + sysedl] + core + [f])
    if with_host:
        host = common + ["-DOE_BUILD_UNTRUSTED", "-D_GNU_SOURCE",
                         '-DOE_REPO_BRANCH_NAME=""', '-DOE_REPO_LAST_COMMIT=""',
                         "-I" + os.path.join(src, "3rdparty", "sgxsdk", "include"),
                         "-I" + os.path.join(gen, "host"), "-I" + inc, "-I" + stage_inc]
        for f in c_files(src, HOST_DIRS):
            cmds.append(host + [f])
    return cmds


def run_compiles(list_file, jobs):
    """Runs under the CodeQL tracer. Compiler errors do not stop extraction,
    so failures are logged and never propagated."""
    cmds = json.load(open(list_file))
    log = os.path.join(os.path.dirname(list_file), "compile-errors.log")

    def one(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True)
        return cmd[-1], r.returncode, r.stderr

    failed = 0
    with open(log, "w") as out, \
            concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for path, rc, err in pool.map(one, cmds):
            if rc != 0:
                failed += 1
                out.write("==== %s (exit %d)\n%s\n" % (path, rc, err))
    print("compiled %d units, %d with compiler errors (see %s)"
          % (len(cmds), failed, log))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--oe-src", help="Open Enclave SDK checkout")
    p.add_argument("--codeql", help="path to the codeql CLI binary")
    p.add_argument("--db", help="output database directory")
    p.add_argument("--work-dir", help="scratch dir (default: <db>.work)")
    p.add_argument("--no-host", action="store_true", help="skip host/ sources")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--run-compiles", help=argparse.SUPPRESS)
    args = p.parse_args()

    if args.run_compiles:
        return run_compiles(args.run_compiles, args.jobs)
    if not (args.oe_src and args.codeql and args.db):
        p.error("--oe-src, --codeql and --db are required")

    src = os.path.abspath(os.path.expanduser(args.oe_src))
    work = os.path.abspath(args.work_dir or args.db.rstrip("/") + ".work")
    os.makedirs(work, exist_ok=True)

    gen, stage_inc, mbedtls_cfg = generate(src, work)
    cmds = compile_commands(src, work, gen, stage_inc, mbedtls_cfg, not args.no_host)
    list_file = os.path.join(work, "compile-commands.json")
    json.dump(cmds, open(list_file, "w"), indent=1)
    print("%d translation units -> %s" % (len(cmds), list_file))

    tracer_cmd = " ".join(shlex.quote(a) for a in [
        sys.executable, os.path.abspath(__file__),
        "--run-compiles", list_file, "--jobs", str(args.jobs)])
    create = [args.codeql, "database", "create", os.path.abspath(args.db),
              "--language=cpp", "--source-root", src, "--command", tracer_cmd,
              "--threads=%d" % args.jobs]
    if args.overwrite:
        create.append("--overwrite")
    run(create)
    return 0


if __name__ == "__main__":
    sys.exit(main())
