/**
 * Provides classes modeling enclave secrets: hardware-derived keys (EGETKEY)
 * and the key material returned by the Open Enclave key APIs.
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import Mitigations

/** A type whose values are key material (`sgx_key_t`, `oe_aes_*_key`, ...). */
class SecretType extends Type {
  SecretType() {
    this.getUnspecifiedType().getName().regexpMatch("_?(sgx_key|oe_seal_key|oe_.*_key_t|.*private_key.*)(_t)?")
  }
}

/**
 * A call that writes key material into the memory designated by argument
 * `getSecretArgument()`.
 */
class SecretProducingCall extends FunctionCall {
  int arg;

  SecretProducingCall() {
    exists(string n | n = this.getTarget().getName() |
      n = ["oe_egetkey", "oe_get_key", "_get_key_imp"] and arg = 1
      or
      n = ["oe_get_seal_key", "oe_get_seal_key_v2", "oe_get_private_key"] and arg = 2
      or
      n = ["oe_get_seal_key_by_policy", "oe_get_seal_key_by_policy_v2"] and arg = 1
      or
      n = "oe_get_private_key_by_policy" and arg = 2
      or
      n = "oe_kdf_derive_key" and arg = 5
      or
      n = "oe_get_report_key" and arg = 0
    )
  }

  /** Gets the argument that receives the secret. */
  Expr getSecretArgument() { result = this.getArgument(arg) }
}

/** A data-flow source of secret data. */
class SecretSource extends DataFlow::Node {
  SecretSource() {
    this.asDefiningArgument() = any(SecretProducingCall c).getSecretArgument()
    or
    this.asExpr().(VariableAccess).getTarget().getType() instanceof SecretType
  }
}

/**
 * A taint step from a struct written as a whole (`oe_get_key(&req, &key)`) to
 * the fields later read from it (`key.buf`).
 */
predicate wholeObjectFieldStep(DataFlow::Node a, DataFlow::Node b) {
  exists(Variable v, DotFieldAccess fa |
    a.asDefiningArgument().(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v and
    fa.getQualifier().(VariableAccess).getTarget() = v
  |
    b.asExpr() = fa or b.asIndirectExpr() = fa
  )
}
