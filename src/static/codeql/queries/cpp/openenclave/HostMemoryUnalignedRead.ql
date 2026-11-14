/**
 * @name Sub-8-byte read of host memory (ÆPIC Leak / xAPIC)
 * @description On processors affected by CVE-2022-21233 (ÆPIC Leak), enclave reads of
 *              untrusted memory that are not 8-byte aligned and 8-byte sized can expose
 *              stale enclave data through the xAPIC MMIO range. Copy host data into
 *              enclave memory with oe_memcpy_aligned and operate on the copy.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id oe/sgx/host-memory-unaligned-read
 * @tags security
 *       sgx
 *       hardware
 *       external/cwe/cwe-1342
 */

import cpp
import openenclave.sgx.Sgx

from Element read, string msg
where
  exists(HostMemoryAccess a | a = read |
    a.isRead() and
    not a.isEightByteGranular() and
    msg =
      "This " + a.getAccessSize() +
        "-byte load from host memory is not an 8-byte aligned, 8-byte sized read; " +
        "copy the data in with oe_memcpy_aligned first."
  )
  or
  exists(MemoryFunctionCall c, Expr src | c = read |
    src = c.getASource() and
    isEnclaveCode(c) and
    pointsToHostMemory(src) and
    not c.isEightByteGranular() and
    msg =
      "'" + c.getTarget().getName() +
        "' reads host memory byte-wise; copy it in with oe_memcpy_aligned instead."
  )
select read, msg
