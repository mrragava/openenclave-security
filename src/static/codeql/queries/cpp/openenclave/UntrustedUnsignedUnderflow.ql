/**
 * @name Unsigned underflow of an untrusted size
 * @description An attacker-influenced unsigned size `n` is used as `n - k` in a loop
 *              bound, index or size where range analysis cannot show `n >= k`. With
 *              `n < k` the subtraction wraps to a huge value and the loop or copy runs
 *              far out of bounds. Inputs are host OCALL data, ECALL inputs and remote
 *              attestation material (evidence, endorsements, sealed blobs).
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id oe/sgx/untrusted-unsigned-underflow
 * @tags security
 *       sgx
 *       external/cwe/cwe-191
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import openenclave.sgx.Sgx
import UnderflowFlow::PathGraph

/**
 * Holds if the condition containing `d` also tests its operand against a
 * constant, as in `n > 0 && p[n - 1]` (range analysis does not see through
 * dereferences such as `*size`).
 */
predicate guardedInSameCondition(SubExpr d) {
  exists(Expr cond, ComparisonOperation cmp |
    cond = any(Loop l).getCondition() or cond = any(IfStmt s).getCondition()
  |
    d.getParent+() = cond and
    cmp.getParent*() = cond and
    globalValueNumber(cmp.getAnOperand()) = globalValueNumber(d.getLeftOperand()) and
    exists(cmp.getAnOperand().getValue())
  )
}

/** A subtraction `n - k` of an unsigned `n` by a positive constant that may wrap. */
class WrappingDecrement extends SubExpr {
  int k;

  WrappingDecrement() {
    this.getUnspecifiedType().(IntegralType).isUnsigned() and
    k = this.getRightOperand().getValue().toInt() and
    k > 0 and
    lowerBound(this.getLeftOperand().getFullyConverted()) < k and
    not guardedInSameCondition(this) and
    (
      exists(Loop l | this.getParent*() = l.getCondition())
      or
      this.getParent*() = any(ArrayExpr a).getArrayOffset()
      or
      this.getParent*() = any(MemoryFunctionCall c).getSizeArgument()
      or
      this.getParent*() = any(AllocationExpr a).getSizeExpr()
    )
  }

  /** Gets the subtracted constant. */
  int getDecrement() { result = k }
}

module UnderflowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n instanceof RemoteFlowSource or
    n instanceof OcallOutput or
    n instanceof EcallInput
  }

  predicate isSink(DataFlow::Node n) { n.asExpr() = any(WrappingDecrement d).getLeftOperand() }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { hostDataCopyStep(a, b) }
}

module UnderflowFlow = TaintTracking::Global<UnderflowConfig>;

from UnderflowFlow::PathNode source, UnderflowFlow::PathNode sink, WrappingDecrement d
where UnderflowFlow::flowPath(source, sink) and sink.getNode().asExpr() = d.getLeftOperand()
select d, source, sink,
  "'" + d.getLeftOperand().toString() + " - " + d.getDecrement() +
    "' wraps when the untrusted size from $@ is less than " + d.getDecrement() + ".",
  source.getNode(), source.getNode().toString()
