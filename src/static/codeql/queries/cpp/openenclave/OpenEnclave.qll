// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
import cpp

/**
 * Function definition model for an OCall function.
 */
class OCallFunction extends Function {
  OCallFunction() { this.getName().matches("%_ocall") }
}

/**
 * Call to an OCall function
 */
class OCallFunctionCall extends FunctionCall {
  OCallFunctionCall() { this.getTarget() instanceof OCallFunction }
}
