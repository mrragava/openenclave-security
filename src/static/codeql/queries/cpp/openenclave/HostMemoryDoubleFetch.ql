/**
 * @name Double fetch of host memory
 * @description A location in untrusted host memory is read in a check and read again
 *              afterwards. The host can change it between the two reads (TOCTOU), so
 *              the value used is not the value that was checked. Copy host data into
 *              enclave memory once, then validate and use the copy.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id oe/sgx/host-memory-double-fetch
 * @tags security
 *       sgx
 *       external/cwe/cwe-367
 */

import cpp
import semmle.code.cpp.controlflow.SSA
import openenclave.sgx.Sgx

/** Holds if `access` reads `path` relative to the pointer held in `baseUse`. */
predicate accessPathFrom(Expr access, VariableAccess baseUse, string path) {
  baseUse = access.(PointerFieldAccess).getQualifier().getUnconverted() and
  path = "->" + access.(PointerFieldAccess).getTarget().getName()
  or
  baseUse = access.(PointerDereferenceExpr).getOperand().getUnconverted() and path = "*"
  or
  exists(string p |
    accessPathFrom(access.(DotFieldAccess).getQualifier(), baseUse, p) and
    path = p + "." + access.(DotFieldAccess).getTarget().getName()
  )
}

/** Holds if `e` is evaluated as part of a check. */
predicate isCheck(Expr e) {
  exists(Expr cond |
    cond = any(IfStmt s).getCondition() or
    cond = any(Loop l).getCondition() or
    cond = any(SwitchStmt s).getExpr() or
    cond = any(ConditionalExpr c).getCondition() or
    cond = any(ComparisonOperation c) or
    cond = any(FunctionCall c | c.getTarget().getName().matches(["oe\\_is\\_%", "oe\\_safe\\_%"]))
  |
    e.getParent*() = cond
  )
}

predicate cfgReaches(ControlFlowNode a, ControlFlowNode b) {
  exists(BasicBlock bb, int i, int j | bb.getNode(i) = a and bb.getNode(j) = b and i < j)
  or
  a.getBasicBlock().getASuccessor+() = b.getBasicBlock()
}

from
  HostMemoryAccess check, HostMemoryAccess use, VariableAccess b1, VariableAccess b2, string path,
  SsaDefinition def, StackVariable v
where
  check.isRead() and
  use.isRead() and
  check != use and
  accessPathFrom(check, b1, path) and
  accessPathFrom(use, b2, path) and
  b1 = def.getAUse(v) and
  b2 = def.getAUse(v) and
  isCheck(check) and
  cfgReaches(check, use) and
  not exists(Expr cond | isCheck(cond) and check.getParent+() = cond and use.getParent+() = cond)
select use,
  "Host memory '" + v.getName() + path + "' is read again after being checked $@; " +
    "the host can modify it in between.", check, "here"
