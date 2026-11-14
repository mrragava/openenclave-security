/**
 * Provides models of the idioms enclave code uses to validate host input:
 * enclave range checks on pointers and bounds checks on sizes and indices.
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.ir.IR
import semmle.code.cpp.ir.dataflow.DataFlow

/** A call to `oe_is_outside_enclave(ptr, size)` or `oe_is_within_enclave(ptr, size)`. */
class EnclaveRangeCheck extends FunctionCall {
  EnclaveRangeCheck() { this.getTarget().hasName(["oe_is_outside_enclave", "oe_is_within_enclave"]) }

  /** Gets the checked pointer. */
  Expr getPointer() { result = this.getArgument(0) }

  /** Gets the checked size. */
  Expr getSize() { result = this.getArgument(1) }

  /** Holds if this check establishes that the range lies in host memory. */
  predicate isOutsideCheck() { this.getTarget().hasName("oe_is_outside_enclave") }
}

private predicate exprVariant(Expr e, Expr v) {
  v = e or v = e.getFullyConverted() or v = e.getUnconverted()
}

/** Holds if `g` evaluating to `branch` implies that `check` returned true. */
private predicate checkSucceeds(IRGuardCondition g, FunctionCall check, boolean branch) {
  exists(GuardValue v, Operand op |
    op.getDef().getUnconvertedResultExpression() = check and
    g.comparesEq(op, 0, false, v) and
    branch = v.asBooleanValue()
  )
  or
  g.getUnconvertedResultExpression() = check and branch = true
}

/** A barrier guard: `e` was validated by an enclave range check. */
predicate rangeCheckGuard(IRGuardCondition g, Expr e, boolean branch) {
  exists(EnclaveRangeCheck c | checkSucceeds(g, c, branch) and exprVariant(c.getPointer(), e))
}

private predicate relevantPath(Expr e) {
  e = any(EnclaveRangeCheck c).getPointer().getUnconverted()
  or
  exists(FieldAccess fa | relevantPath(fa) and e = fa.getQualifier().getUnconverted())
}

/** Holds if `checked` and `use` read the same variable/field access path. */
private predicate sameAccessPath(Expr checked, Expr use) {
  relevantPath(checked) and
  use.getEnclosingFunction() = checked.getEnclosingFunction() and
  (
    not checked instanceof FieldAccess and
    not use instanceof FieldAccess and
    checked.(VariableAccess).getTarget() = use.(VariableAccess).getTarget()
    or
    checked.(FieldAccess).getTarget() = use.(FieldAccess).getTarget() and
    sameAccessPath(checked.(FieldAccess).getQualifier().getUnconverted(),
      use.(FieldAccess).getQualifier().getUnconverted())
  )
}

/**
 * Holds if `use` reads the same access path as the pointer of a range check
 * whose success dominates `use`. This complements value-number based barrier
 * guards when a call between the check and the use clobbers the value number.
 */
predicate dominatedByRangeCheck(Expr use) {
  exists(EnclaveRangeCheck c, GuardCondition g |
    g.ensuresEq(c, 0, use.getBasicBlock(), false) and
    sameAccessPath(c.getPointer().getUnconverted(), use.getUnconverted())
  )
}

/**
 * A barrier guard: when `g` evaluates to `branch`, `e` is bounded from above
 * (for example `if (n > max) fail;`) or compared for equality.
 */
predicate upperBoundGuard(IRGuardCondition g, Expr e, boolean branch) {
  exists(Operand bounded | exprVariant(bounded.getDef().getUnconvertedResultExpression(), e) |
    g.comparesLt(bounded, _, _, true, branch)
    or
    g.comparesLt(_, bounded, _, false, branch)
    or
    exists(GuardValue v |
      g.comparesLt(bounded, _, true, v) and branch = v.asBooleanValue()
      or
      g.comparesEq(bounded, _, true, v) and branch = v.asBooleanValue()
    )
    or
    g.comparesEq(bounded, _, _, true, branch)
  )
}
