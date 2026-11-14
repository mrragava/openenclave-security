/**
 * @name Lock held across an OCALL
 * @description The enclave calls into the host while holding a lock. The host decides
 *              when (and whether) the OCALL returns, so it can hold every other enclave
 *              thread that needs the lock indefinitely and freely schedule the race
 *              windows around it.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 4.0
 * @precision medium
 * @id oe/sgx/lock-held-across-ocall
 * @tags reliability
 *       security
 *       sgx
 *       external/cwe/cwe-833
 */

import cpp
import openenclave.sgx.Sgx

from LockAcquire acq, FunctionCall ocall
where
  isEnclaveCode(acq) and
  heldAt(acq, ocall) and
  (
    ocall instanceof OcallProxyCall
    or
    ocall.getTarget().getName() =
      ["oe_ocall", "oe_host_printf", "oe_host_fprintf", "oe_host_write", "oe_host_malloc",
          "oe_host_free", "oe_host_calloc", "oe_host_realloc"]
  )
select ocall, "OCALL '" + ocall.getTarget().getName() + "' is made while holding the lock taken $@.",
  acq, "here"
