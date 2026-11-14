/**
 * Provides classes for lock discipline in enclave code. Inside an enclave a
 * lock misuse is worse than in a normal process: OCALLs and AEX let the host
 * stall a thread at any point, widening every race window indefinitely.
 */

import cpp
import semmle.code.cpp.controlflow.Guards
import Mitigations

/** A call that acquires a lock. */
class LockAcquire extends FunctionCall {
  LockAcquire() {
    this.getTarget().getName() =
      [
        "oe_spin_lock", "oe_mutex_lock", "oe_rwlock_rdlock", "oe_rwlock_wrlock",
        "pthread_mutex_lock", "pthread_spin_lock", "pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock"
      ]
  }

  /** Gets the expression designating the lock. */
  Expr getLock() { result = this.getArgument(0) }
}

/** A call that releases a lock. */
class LockRelease extends FunctionCall {
  LockRelease() {
    this.getTarget().getName() =
      [
        "oe_spin_unlock", "oe_mutex_unlock", "oe_rwlock_unlock", "oe_rwlock_rdunlock",
        "oe_rwlock_wrunlock", "pthread_mutex_unlock", "pthread_spin_unlock",
        "pthread_rwlock_unlock"
      ]
  }

  /** Gets the expression designating the lock. */
  Expr getLock() { result = this.getArgument(0) }
}

private predicate lockOperand(Expr e) {
  e = any(LockAcquire a).getLock() or e = any(LockRelease r).getLock()
}

/** Holds if `e` designates the lock reached by `path` from variable `base`. */
private predicate accessPath(Expr e, Variable base, string path) {
  exists(Expr u | u = e.getUnconverted() |
    not u instanceof FieldAccess and
    base = u.(VariableAccess).getTarget() and
    path = ""
    or
    exists(FieldAccess fa, string p | fa = u |
      accessPath(fa.getQualifier(), base, p) and path = p + "." + fa.getTarget().getName()
    )
  )
}

/** Holds if lock expression `e` designates the lock `(base, path)`. */
predicate lockDesignator(Expr e, Variable base, string path) {
  lockOperand(e) and
  exists(Expr u | u = e.getUnconverted() |
    accessPath(u.(AddressOfExpr).getOperand(), base, path)
    or
    not u instanceof AddressOfExpr and accessPath(u, base, "*" + path)
  )
}

/** Holds if `a` and `b` designate the same lock. */
predicate sameLock(Expr a, Expr b) {
  exists(Variable v, string p | lockDesignator(a, v, p) and lockDesignator(b, v, p))
}

/** Holds if control-flow node `n` releases the lock acquired by `acq`. */
private predicate releases(ControlFlowNode n, LockAcquire acq) {
  sameLock(n.(LockRelease).getLock(), acq.getLock())
}

/** Holds if `e` holds the status returned by `acq`: the call or a variable assigned from it. */
private predicate lockStatus(LockAcquire acq, Expr e) {
  e = acq
  or
  exists(Variable v |
    v.getAnAssignedValue().getUnconverted() = acq and e.(VariableAccess).getTarget() = v
  )
}

/** Holds if `bb` executes only when `acq` succeeded (`true`) or failed (`false`). */
private predicate acquireOutcome(LockAcquire acq, BasicBlock bb, boolean succeeded) {
  exists(GuardCondition g, Expr s | lockStatus(acq, s) | g.ensuresEq(s, 0, bb, succeeded))
}

/** Holds if `bb` executes only when flag variable `v` is `value`. */
private predicate flagIs(Variable v, BasicBlock bb, boolean value) {
  exists(GuardCondition g | g.(VariableAccess).getTarget() = v and g.controls(bb, value))
}

/**
 * Holds if flag `v` is set to `value` next to `call`: in the same basic block,
 * or within the blocks of a status check such as
 * `OE_CHECK(lock(...)); locked = true;` (which expands to `do { if } while (0)`).
 */
private predicate setsFlag(FunctionCall call, Variable v, boolean value) {
  exists(AssignExpr a, BasicBlock b |
    a.getLValue().(VariableAccess).getTarget() = v and
    b = call.getBasicBlock() and
    (
      a.getBasicBlock() = b or
      a.getBasicBlock() = b.getASuccessor() or
      a.getBasicBlock() = b.getASuccessor().getASuccessor() or
      a.getBasicBlock() = b.getASuccessor().getASuccessor().getASuccessor()
    ) and
    (
      a.getRValue().getValue() = ["1", "true"] and value = true
      or
      a.getRValue().getValue() = ["0", "false"] and value = false
    )
  )
}

/**
 * Holds if variable `v` records that `acq` holds the lock: it is set right
 * after the acquire, or it guards the acquire (`if (need_lock) lock(...)`).
 */
private predicate lockFlag(LockAcquire acq, Variable v) {
  setsFlag(acq, v, true) or flagIs(v, acq.getBasicBlock(), true)
}

/**
 * Holds if the lock is passed to a callee at `c` that may release it, for
 * example `return _wake_waiters(rw_lock);`.
 */
private predicate handsOffLock(LockAcquire acq, FunctionCall c) {
  not c instanceof LockAcquire and
  not c instanceof LockRelease and
  exists(Variable base |
    lockDesignator(acq.getLock(), base, _) and
    not base instanceof GlobalVariable and
    c.getAnArgument().getUnconverted().(VariableAccess).getTarget() = base
  )
}

/** Holds if `bb` cannot execute while `acq` holds the lock (infeasible on correlated branches). */
private predicate notHeldIn(LockAcquire acq, BasicBlock bb) {
  acquireOutcome(acq, bb, false)
  or
  exists(Variable v | lockFlag(acq, v) and flagIs(v, bb, false))
}

/**
 * Holds if the branch `cond -> succ` cannot be taken while `acq` holds the lock:
 * the false edge of `if (locked)`, or the failure edge of a lock-status test.
 */
private predicate infeasibleEdge(LockAcquire acq, ControlFlowNode cond, ControlFlowNode succ) {
  exists(Variable v | lockFlag(acq, v) |
    cond.(VariableAccess).getTarget() = v and succ = cond.getAFalseSuccessor()
    or
    cond.(NotExpr).getOperand().(VariableAccess).getTarget() = v and
    succ = cond.getATrueSuccessor()
  )
  or
  exists(Expr s | lockStatus(acq, s) |
    cond.(EQExpr).getAnOperand() = s and
    cond.(EQExpr).getAnOperand().getValue() = "0" and
    succ = cond.getAFalseSuccessor()
    or
    cond.(NEExpr).getAnOperand() = s and
    cond.(NEExpr).getAnOperand().getValue() = "0" and
    succ = cond.getATrueSuccessor()
  )
}

/** Holds if `n` is reachable from `acq` while the lock is still held. */
predicate heldAt(LockAcquire acq, ControlFlowNode n) {
  n = acq
  or
  exists(ControlFlowNode mid | heldAt(acq, mid) |
    n = mid.getASuccessor() and
    not releases(mid, acq) and
    not handsOffLock(acq, mid) and
    not mid instanceof NonReturningCall and
    not notHeldIn(acq, n.getBasicBlock()) and
    not infeasibleEdge(acq, mid, n)
  )
}

/** Holds if `bb` cannot execute after `rel` released the lock. */
private predicate stillReleasedImpossible(LockRelease rel, BasicBlock bb) {
  exists(Variable v | setsFlag(rel, v, false) and flagIs(v, bb, true))
}

/** Holds if `n` is reachable from `rel` without re-acquiring the lock. */
predicate releasedAt(LockRelease rel, ControlFlowNode n) {
  n = rel.getASuccessor() and not stillReleasedImpossible(rel, n.getBasicBlock())
  or
  exists(ControlFlowNode mid | releasedAt(rel, mid) |
    n = mid.getASuccessor() and
    not sameLock(mid.(LockAcquire).getLock(), rel.getLock()) and
    not mid instanceof NonReturningCall and
    not stillReleasedImpossible(rel, n.getBasicBlock())
  )
}

/** Holds if `rel` is reachable from the entry of its function without acquiring the lock. */
private predicate unheldBefore(LockRelease rel, ControlFlowNode n) {
  n = rel
  or
  exists(ControlFlowNode mid | unheldBefore(rel, mid) |
    n = mid.getAPredecessor() and
    not sameLock(n.(LockAcquire).getLock(), rel.getLock())
  )
}

/** Holds if `rel` executes only on paths where its acquire succeeded or its lock flag is set. */
private predicate guardedByAcquire(LockRelease rel) {
  exists(LockAcquire acq | sameLock(acq.getLock(), rel.getLock()) |
    acquireOutcome(acq, rel.getBasicBlock(), true)
    or
    exists(Variable v | lockFlag(acq, v) and flagIs(v, rel.getBasicBlock(), true))
  )
}

/** Holds if `rel` can execute on a path where its function never acquired the lock. */
predicate releasedWithoutAcquire(LockRelease rel) {
  unheldBefore(rel, rel.getEnclosingFunction().getEntryPoint()) and
  not guardedByAcquire(rel) and
  exists(LockAcquire acq |
    acq.getEnclosingFunction() = rel.getEnclosingFunction() and sameLock(acq.getLock(), rel.getLock())
  )
}
