/**
 * @name Enclave secret not securely erased
 * @description A stack buffer receives key material (EGETKEY output, seal keys,
 *              derived keys) and can go out of scope without oe_secure_zero_fill on
 *              some path, or is erased only with memset, which the compiler may remove
 *              as a dead store. Leftover keys on the enclave stack are exposed to later
 *              memory-safety bugs and to transient-execution leaks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id oe/sgx/secret-not-zeroized
 * @tags security
 *       sgx
 *       external/cwe/cwe-226
 *       external/cwe/cwe-14
 */

import cpp
import openenclave.sgx.Sgx

/**
 * Holds if `call` writes a secret into local variable `v`. Pointer variables
 * only receive the address of a heap key buffer that is handed to the caller.
 */
predicate secretInto(SecretProducingCall call, LocalVariable v) {
  not v.getUnspecifiedType() instanceof PointerType and
  exists(Expr arg | arg = call.getSecretArgument().getUnconverted() |
    arg.(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v
    or
    arg.(VariableAccess).getTarget() = v and v.getUnspecifiedType() instanceof ArrayType
  )
}

/** Holds if `c` erases `v` (securely when `secure` is true). */
predicate erases(FunctionCall c, LocalVariable v, boolean secure) {
  exists(Expr arg | arg = c.getArgument(0).getUnconverted() |
    arg.(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v or
    arg.(VariableAccess).getTarget() = v
  ) and
  (
    c.getTarget() instanceof SecureZeroFunction and secure = true
    or
    c.getTarget().getName() = ["memset", "oe_memset", "bzero"] and secure = false
  )
}

/** Holds if `n` is reachable from `call` without `v` having been erased securely. */
predicate liveSecret(SecretProducingCall call, LocalVariable v, ControlFlowNode n) {
  secretInto(call, v) and n = call
  or
  exists(ControlFlowNode mid | liveSecret(call, v, mid) |
    n = mid.getASuccessor() and
    not erases(mid, v, true) and
    not mid instanceof NonReturningCall
  )
}

from SecretProducingCall call, LocalVariable v, string msg
where
  isEnclaveCode(call) and
  liveSecret(call, v, call.getEnclosingFunction()) and
  if exists(FunctionCall m | erases(m, v, false) and m.getEnclosingFunction() = call.getEnclosingFunction())
  then msg = "Secret written to '" + v.getName() + "' is erased only with memset, which may be optimized away."
  else msg = "Secret written to '" + v.getName() + "' can leave this function without oe_secure_zero_fill."
select call, msg
