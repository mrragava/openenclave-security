/**
 * @name Dereference of an unvalidated host pointer in enclave code
 * @description A pointer chosen by the host (a [user_check] ECALL parameter, a raw
 *              EENTER/ORET register value or a pointer stored in an ABI structure) is
 *              dereferenced without oe_is_outside_enclave/oe_is_within_enclave. The host
 *              can point it into enclave memory and read or corrupt enclave secrets.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id oe/sgx/host-pointer-unvalidated-deref
 * @tags security
 *       sgx
 *       external/cwe/cwe-822
 */

import cpp
import openenclave.sgx.Sgx
import HostPointerFlow::PathGraph

module HostPointerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof HostChosenPointer }

  predicate isSink(DataFlow::Node n) {
    exists(Expr e | isAccessBase(e) and n.asExpr() = e.getUnconverted()) and
    isEnclaveNode(n)
  }

  predicate isBarrier(DataFlow::Node n) {
    n = DataFlow::BarrierGuard<rangeCheckGuard/3>::getABarrierNode()
    or
    dominatedByRangeCheck(n.asExpr())
    or
    n.getFunction() instanceof BarrierWriteFunction
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    pointerDerivationStep(a.asExpr(), b.asExpr())
  }
}

module HostPointerFlow = DataFlow::Global<HostPointerConfig>;

from HostPointerFlow::PathNode source, HostPointerFlow::PathNode sink
where HostPointerFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Host-controlled pointer from $@ is dereferenced without an enclave range check.",
  source.getNode(), source.getNode().toString()
