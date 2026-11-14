/**
 * @name Spectre v1 gadget on host-controlled index without lfence
 * @description A host-controlled index is bounds-checked and then used to load from a
 *              table, and the loaded value is dereferenced or called. Without an lfence
 *              (oe_lfence) between the check and the load, the CPU can speculatively load
 *              out of bounds and leak or redirect through the dependent access
 *              (bounds check bypass, CVE-2017-5753). Speculative load hardening, when
 *              enabled for the build, mitigates this at compile time.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.6
 * @precision medium
 * @id oe/sgx/spectre-v1-indexed-load
 * @tags security
 *       sgx
 *       hardware
 *       external/cwe/cwe-1037
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance
import openenclave.sgx.Sgx
import IndexFlow::PathGraph

module IndexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n instanceof OcallOutput or
    n instanceof EcallInput or
    n instanceof HostChosenPointer or
    n.asExpr().(HostMemoryAccess).isRead()
  }

  predicate isSink(DataFlow::Node n) {
    n.asExpr() = any(ArrayExpr a).getArrayOffset() and isEnclaveNode(n)
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { hostDataCopyStep(a, b) }
}

module IndexFlow = TaintTracking::Global<IndexConfig>;

/** Holds if the value loaded by `load` is dereferenced or called. */
predicate feedsDependentAccess(ArrayExpr load, string kind) {
  exists(DataFlow::Node use | DataFlow::localFlow(DataFlow::exprNode(load), use) |
    use.asExpr() = any(ExprCall c).getExpr() and kind = "called"
    or
    isAccessBase(use.asExpr()) and kind = "dereferenced"
    or
    use.asExpr() = any(ArrayExpr a).getArrayOffset() and kind = "used as an index"
  )
}

/** Holds if `e` reads variable `base` through the field chain `path`. */
predicate accessChain(Expr e, Variable base, string path) {
  exists(Expr u | u = e.getUnconverted() |
    not u instanceof FieldAccess and base = u.(VariableAccess).getTarget() and path = ""
    or
    exists(FieldAccess fa, string p | fa = u |
      accessChain(fa.getQualifier(), base, p) and path = p + "." + fa.getTarget().getName()
    )
  )
}

/** Holds if `load` is only reached when its index passed an upper-bound check `g`. */
predicate boundsChecked(ArrayExpr load, GuardCondition g) {
  exists(Expr checked, Variable v, string p |
    g.ensuresLt(checked, _, _, load.getBasicBlock(), true) and
    accessChain(checked, v, p) and
    accessChain(load.getArrayOffset(), v, p)
  )
}

/** Holds if a speculation barrier lies between guard `g` and `load`. */
predicate fenced(GuardCondition g, ArrayExpr load) {
  exists(SpeculationBarrier b |
    b.getEnclosingFunction() = load.getEnclosingFunction() and
    bbDominates(b.getBasicBlock(), load.getBasicBlock()) and
    bbDominates(g.(Expr).getBasicBlock(), b.getBasicBlock())
  )
}

from IndexFlow::PathNode source, IndexFlow::PathNode sink, ArrayExpr load, GuardCondition g, string kind
where
  IndexFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = load.getArrayOffset() and
  boundsChecked(load, g) and
  not fenced(g, load) and
  feedsDependentAccess(load, kind)
select load, source, sink,
  "Bounds-checked load indexed by host-controlled $@ is " + kind +
    " with no lfence after the check $@.", source.getNode(), source.getNode().toString(), g,
  "here"
