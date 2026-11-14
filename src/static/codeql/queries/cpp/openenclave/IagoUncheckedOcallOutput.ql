/**
 * @name Unchecked host-controlled OCALL output used as size or index (Iago)
 * @description A value returned by the untrusted host (an OCALL return value, an [out]
 *              parameter or data read from host memory) is used as a memory-copy size,
 *              allocation size, array index, pointer offset or loop bound without an
 *              upper-bound check. A malicious host can return any value.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id oe/sgx/iago-unchecked-ocall-output
 * @tags security
 *       sgx
 *       external/cwe/cwe-20
 *       external/cwe/cwe-129
 *       external/cwe/cwe-805
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import openenclave.sgx.Sgx
import IagoFlow::PathGraph

/** Holds if `e` is used in a way where an out-of-range value corrupts or leaks memory. */
predicate sizeOrIndexUse(Expr e, string what) {
  // The *_s variants check the count against the destination size themselves.
  e = any(MemoryFunctionCall c | not c.getTarget().getName().matches("%\\_s%")).getSizeArgument() and
  what = "a memory access size"
  or
  e = any(AllocationExpr a).getSizeExpr() and what = "an allocation size"
  or
  e = any(ArrayExpr a).getArrayOffset() and what = "an array index"
  or
  exists(PointerAddExpr p | e = p.getAnOperand() and e.getUnspecifiedType() instanceof IntegralType) and
  what = "a pointer offset"
  or
  e = any(AssignPointerAddExpr p).getRValue() and what = "a pointer offset"
  or
  exists(Loop l, RelationalOperation r |
    r.getParent*() = l.getCondition() and
    e = r.getAnOperand() and
    e.getUnspecifiedType() instanceof IntegralType
  ) and
  what = "a loop bound"
}

/** A function that bounds its count argument by the destination size itself. */
class CheckedCopyFunction extends Function {
  CheckedCopyFunction() { this.getName().regexpMatch("oe_(mem(cpy|move|set)|str(n?cpy|n?cat))_s(_with_barrier)?") }
}

module IagoConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n instanceof OcallOutput
    or
    exists(HostMemoryAccess a |
      a.isRead() and n.asExpr() = a and a.getUnspecifiedType() instanceof IntegralType
    )
  }

  predicate isSink(DataFlow::Node n) {
    sizeOrIndexUse(n.asExpr(), _) and
    isEnclaveNode(n) and
    not isGeneratedEdgeFile(n.getLocation().getFile())
  }

  predicate isBarrier(DataFlow::Node n) {
    n = DataFlow::BarrierGuard<upperBoundGuard/3>::getABarrierNode()
    or
    n.asExpr().getUnspecifiedType() instanceof BoolType
    or
    n.getFunction() instanceof CheckedCopyFunction
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { hostDataCopyStep(a, b) }
}

module IagoFlow = TaintTracking::Global<IagoConfig>;

from IagoFlow::PathNode source, IagoFlow::PathNode sink, string what
where IagoFlow::flowPath(source, sink) and sizeOrIndexUse(sink.getNode().asExpr(), what)
select sink.getNode(), source, sink,
  "Host-controlled value from $@ is used as " + what + " without an upper-bound check.",
  source.getNode(), source.getNode().toString()
