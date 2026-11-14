# CodeQL Static Analysis on Open Enclave

## CodeQL Introduction
CodeQL is a static analysis engine used by developers to automate security checks, and by security researchers to perform variant analysis.

Unlike traditional static analysis tools CodeQL provides an ability to extend the analysis via custom queries in addition to the built-in queries.
The following steps show how to run CodeQL analysis on Linux, However CodeQL supports both Linux and Windows.

## Layout

| Path | Pack | Contents |
|---|---|---|
| `lib/cpp` | `openenclave/sgx-all` | QL model of the SGX trust boundary (`openenclave/sgx/*.qll`): enclave code, oeedger8r ECALL/OCALL stubs, host-controlled values, host memory, validation idioms, HW-vulnerability mitigations, locks, secrets |
| `models/cpp` | `openenclave/sgx-models` | Data extensions: OE allocators, asm-backed copy summaries, attestation inputs, and EDL-generated sources/sinks (`ext/generated/`) |
| `queries/cpp` | `openenclave-codeql-cpp` | Queries (`openenclave/`; the SGX queries have `oe/sgx/` IDs), suites |
| `test/cpp` | `openenclave/sgx-tests` | `codeql test run` regression tests for the SGX queries |
| `codeql` | submodule | `github/codeql` at tag `codeql-cli/v2.27.4`; must match the CLI version in `scripts/codeql.config` |

## Running CodeQL analysis on Open Enclave
1. Run `scripts/codeql.py [--clean] [--builtin] [--scan_path=<openenclave checkout>]`
    - It downloads the CodeQL CLI version pinned in `scripts/codeql.config`.
    - Builds the CodeQL database with `scripts/build_oe_codeql_db.py` (see below).
    - Runs the Open Enclave query suite (`--builtin` adds the selected standard CodeQL security queries) with the `openenclave/sgx-models` model pack, and writes `build/OpenEnclave.sarif`.
2. Install [CodeQL extension for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql) or [SARIF viewer extension](https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer).
3. Open OpenEnclave.sarif from build folder in Visual Studio Code to see results in results tab.

### Building the database
The SDK's CMake build only generates oeedger8r *headers*; the ECALL/OCALL stubs that implement the host/enclave boundary are generated into each enclave application. `build_oe_codeql_db.py` builds oeedger8r, generates trusted stubs for all system EDLs, stages the generated headers (EDL structures, musl, mbedTLS config) and traces compile-only builds, so no CMake configuration is needed:

    scripts/build_oe_codeql_db.py --oe-src <openenclave> --codeql <codeql-cli> --db build/oe-enclave-db --no-host

Use `--no-host` for the enclave queries. With host sources in the same database, enclave proxies and host implementations of the same ECALL/OCALL names share C linkage and are merged into one function, which hides data flow.

### Modeling an enclave application's EDL
`scripts/edl2codeql.py` parses EDL into a typed AST with the grammar and import semantics of oeedger8r (including `#ifdef`), derives what each ECALL and OCALL moves across the enclave boundary from the code oeedger8r generates, and writes CodeQL models. It expects EDL that oeedger8r accepts: syntax and import errors are reported, oeedger8r's checks of attribute combinations are not repeated. Generate models for the application's EDL and drop them into `models/cpp/ext/generated/`, passing the same `-D` options and search paths as the enclave's oeedger8r invocation:

    scripts/edl2codeql.py --search-path <openenclave>/include --lint \
        --out models/cpp/ext/generated/myenclave.model.yml myenclave.edl

Members of EDL structs and unions are modeled one by one (`Field[...]` access paths that follow oeedger8r's deep-copy rules), because CodeQL's C++ taint tracking does not consider the members of a tainted struct tainted. The `remote` sources and `remote-sink` sinks also make the standard CodeQL queries treat OCALL results and ECALL inputs as attacker controlled, and OCALL inputs as sent to a remote party, when run with `--model-packs openenclave/sgx-models`.

`--lint` reports risky EDL patterns (`[user_check]` and unannotated pointers, host pointers inside structs, pointer-returning calls, `[in,out]` on read-style OCALLs, `size=` smaller than the type, signed sizes) as `file:line:column: warning: ...` lines. `--check` exits with 1 when the model file is out of date, and `--dump-ast` prints the parsed AST. The system EDL model is regenerated with:

    scripts/edl2codeql.py --search-path <openenclave>/include -D OE_SGX_ENTROPY \
        --out models/cpp/ext/generated/oe-system-edl.model.yml \
        <openenclave>/include/openenclave/edl/core.edl \
        <openenclave>/include/openenclave/edl/sgx/platform.edl \
        <openenclave>/include/openenclave/edl/syscall.edl

Run the generator's tests with `python3 -m unittest discover -s scripts/tests`; set `OE_SRC` (an Open Enclave checkout) and `OEEDGER8R` (an oeedger8r binary) to include the corpus and differential tests.

### Running queries directly

    codeql database analyze build/oe-enclave-db queries/cpp/suites/oe-sgx-security.qls \
        --search-path codeql --additional-packs . --format=sarif-latest --output=oe-sgx.sarif
    codeql test run --search-path codeql --additional-packs . test/cpp/sgx

## To run a selected query in Visual Studio Code
1. Add the database (openenclave-codeql-db) in CodeQL extension.
2. Navigate to queries/cpp/openenclave and select a query.
3. Right-click a query and select "Run Queries in selected files" or Open the query annd select "CodeQL: Run a query" in Ctrl+Shift+P.

**References to learn more about CodeQL:**
* [CodeQL Introduction](https://codeql.github.com/docs/codeql-overview/about-codeql/)
* [QL Language basics](https://codeql.github.com/docs/ql-language-reference/)
* [CodeQL for C and C++](https://codeql.github.com/docs/codeql-language-guides/codeql-for-cpp/)
* [Customizing library models for C and C++](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-cpp/)
* [CodeQL Library](https://github.com/github/codeql)
* [CodeQL for Visual Studio Code](https://codeql.github.com/docs/codeql-for-visual-studio-code/)
