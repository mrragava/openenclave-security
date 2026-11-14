/**
 * @name Enclave secret disclosed to the host
 * @description Key material reaches an OCALL argument, a host print/log helper or a
 *              buffer handed to the host. Anything passed to the host is readable by
 *              the attacker the enclave is meant to protect against.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.6
 * @precision medium
 * @id oe/sgx/secret-to-host
 * @tags security
 *       sgx
 *       external/cwe/cwe-200
 *       external/cwe/cwe-532
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
private import semmle.code.cpp.dataflow.ExternalFlow as ExternalFlow
import openenclave.sgx.Sgx
import SecretToHostFlow::PathGraph

module SecretToHostConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof SecretSource }

  predicate isSink(DataFlow::Node n) {
    ExternalFlow::sinkNode(n, "oe-host-disclosure")
    or
    exists(MemoryFunctionCall c |
      pointsToHostMemory(c.getDestination()) and
      n.asIndirectExpr() = c.getASource()
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    // Encryption output may leave the enclave.
    n.asDefiningArgument() =
      any(FunctionCall c |
        c.getTarget().getName().matches(["%encrypt%", "%seal%", "%sign%", "%sha%", "%hash%"])
      ).getAnArgument()
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { wholeObjectFieldStep(a, b) }
}

module SecretToHostFlow = TaintTracking::Global<SecretToHostConfig>;

from SecretToHostFlow::PathNode source, SecretToHostFlow::PathNode sink
where SecretToHostFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Secret from $@ is handed to the untrusted host.",
  source.getNode(), source.getNode().toString()
