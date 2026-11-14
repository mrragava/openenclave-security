/**
 * @name Host-invoked teardown leaves the enclave callable
 * @description The ECALL dispatcher runs enclave teardown (finalizers, attester and
 *              verifier shutdown, allocator cleanup) on host request, but no path
 *              through the teardown updates the status variable that the entry gate
 *              checks. The host can keep issuing ECALLs, or return from a pending OCALL,
 *              into torn-down state (use after finalization).
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.3
 * @precision medium
 * @id oe/sgx/teardown-without-terminal-state
 * @tags security
 *       sgx
 *       external/cwe/cwe-672
 */

import cpp
import openenclave.sgx.Sgx

/** A function that releases enclave-global state. */
class TeardownFunction extends Function {
  TeardownFunction() {
    this.getName() =
      [
        "oe_allocator_cleanup", "oe_attester_shutdown", "oe_verifier_shutdown",
        "oe_call_fini_functions", "oe_call_atexit_functions"
      ]
  }
}

/** A global variable that the host entry point consults before dispatching. */
class EntryGateVariable extends GlobalVariable {
  EntryGateVariable() {
    exists(Function entry, Expr cond |
      entry.hasName("__oe_handle_main") and
      cond.getEnclosingFunction() = entry and
      (cond = any(SwitchStmt s).getExpr() or cond = any(IfStmt s).getCondition()) and
      cond.getAChild*().(VariableAccess).getTarget() = this
    )
  }
}

/** Holds if `f`, or a function it calls, assigns `v` outside an abort path. */
predicate mayWrite(Function f, Variable v) {
  exists(Assignment a |
    a.getLValue().(VariableAccess).getTarget() = v and
    f.calls*(a.getEnclosingFunction()) and
    not a.getEnclosingFunction().getName().matches("%abort%")
  )
}

from FunctionCall teardown, Function dispatcher, EntryGateVariable gate
where
  dispatcher.hasName("_handle_ecall") and
  teardown.getEnclosingFunction() = dispatcher and
  teardown.getTarget().calls*(any(TeardownFunction t)) and
  not mayWrite(teardown.getTarget(), gate)
select teardown,
  "Teardown through '" + teardown.getTarget().getName() + "' never updates '" + gate.getName() +
    "', which gates host entry; later ECALLs and OCALL returns still reach torn-down state."
