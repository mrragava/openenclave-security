/**
 * @name Non-constant-time comparison of secret data
 * @description Key material, MACs or tags are compared with memcmp/strcmp, whose
 *              running time depends on the first differing byte. An attacker who can
 *              time the enclave (SGX-Step, cache and page-fault channels give the host
 *              precise timing) can forge MACs byte by byte. Use
 *              oe_constant_time_mem_equal.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision medium
 * @id oe/sgx/non-constant-time-secret-compare
 * @tags security
 *       sgx
 *       external/cwe/cwe-208
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import openenclave.sgx.Sgx
import SecretCompareFlow::PathGraph

/** A call to a function producing a MAC or tag over secret data. */
class MacOutput extends DataFlow::Node {
  MacOutput() {
    exists(FunctionCall c, string n | n = c.getTarget().getName() |
      n = ["oe_aes_cmac_sign", "mbedtls_cipher_cmac_finish", "mbedtls_md_hmac_finish"] and
      this.asDefiningArgument() = c.getArgument(c.getNumberOfArguments() - 1)
      or
      n = "oe_hmac_sha256_final" and this.asDefiningArgument() = c.getArgument(1)
    )
  }
}

module SecretCompareConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof SecretSource or n instanceof MacOutput }

  predicate isSink(DataFlow::Node n) {
    exists(FunctionCall c |
      c.getTarget().getName() =
        ["memcmp", "oe_memcmp", "bcmp", "strcmp", "oe_strcmp", "strncmp", "oe_strncmp"] and
      (n.asIndirectExpr() = c.getArgument([0, 1]) or n.asExpr() = c.getArgument([0, 1]))
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { wholeObjectFieldStep(a, b) }
}

module SecretCompareFlow = TaintTracking::Global<SecretCompareConfig>;

from SecretCompareFlow::PathNode source, SecretCompareFlow::PathNode sink
where SecretCompareFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Secret data from $@ is compared with a variable-time function.", source.getNode(),
  source.getNode().toString()
