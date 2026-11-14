/**
 * Provides the EDL description of the enclave interface.
 *
 * The tables are populated by data extensions that `scripts/edl2codeql.py`
 * generates from the EDL files of the analyzed enclave (the system EDLs of
 * Open Enclave are generated into `ext/generated/`).
 */

import cpp

/**
 * Holds if the EDL declares function `name` on `side` ("trusted" for ECALLs,
 * "untrusted" for OCALLs) with the given return type and trailing flags.
 */
extensible predicate oeEdlFunction(string name, string side, string returnType, string flags);

/**
 * Holds if parameter `index` of EDL function `function` has the given name,
 * type and comma-separated attributes (for example `in,size=len`).
 */
extensible predicate oeEdlParameter(
  string function, int index, string name, string type, string attributes
);

/** A function declared in an EDL file. */
class EdlFunction extends Function {
  string side;
  string returnType;

  EdlFunction() { oeEdlFunction(this.getName(), side, returnType, _) }

  /** Holds if this is an ECALL, implemented inside the enclave. */
  predicate isEcall() { side = "trusted" }

  /** Holds if this is an OCALL, called by the enclave through a generated proxy. */
  predicate isOcall() { side = "untrusted" }

  /** Gets the EDL return type. */
  string getEdlReturnType() { result = returnType }

  /** Holds if EDL parameter `edlIndex` has attribute `attr` (`size=n` yields `size`). */
  predicate hasParamAttribute(int edlIndex, string attr) {
    exists(string attrs | oeEdlParameter(this.getName(), edlIndex, _, _, attrs) |
      attr = attrs.splitAt(",").regexpReplaceAll("=.*", "")
    )
  }

  /**
   * Gets the argument index, at a call to the enclave-side proxy, of EDL
   * parameter `edlIndex`. OCALL proxies take `_retval` as their first argument.
   */
  int getProxyArgumentIndex(int edlIndex) {
    oeEdlParameter(this.getName(), edlIndex, _, _, _) and
    if this.isOcall() and returnType != "void" then result = edlIndex + 1 else result = edlIndex
  }
}
