/**
 * @name Partial write to host memory without MMIO stale-data barrier
 * @description On processors affected by the MMIO stale data vulnerabilities
 *              (CVE-2022-21123, CVE-2022-21125, CVE-2022-21166), an enclave write to
 *              untrusted memory that is not an 8-byte aligned, 8-byte sized store can
 *              leak stale enclave data to the host. Open Enclave writes host memory
 *              with OE_WRITE_VALUE_WITH_BARRIER or the oe_*_with_barrier functions.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id oe/sgx/host-memory-write-without-barrier
 * @tags security
 *       sgx
 *       hardware
 *       external/cwe/cwe-1342
 */

import cpp
import openenclave.sgx.Sgx

from Element write, string msg
where
  exists(HostMemoryAccess a | a = write |
    a.isWrite() and
    not a.isEightByteGranular() and
    msg =
      "This " + a.getAccessSize() +
        "-byte store to host memory is not an 8-byte aligned, 8-byte sized write; " +
        "use OE_WRITE_VALUE_WITH_BARRIER."
  )
  or
  exists(MemoryFunctionCall c | c = write |
    isEnclaveCode(c) and
    pointsToHostMemory(c.getDestination()) and
    not c.isBarrierWrite() and
    not c.isEightByteGranular() and
    msg =
      "'" + c.getTarget().getName() +
        "' writes host memory byte-wise without a barrier; use the oe_*_with_barrier variant."
  )
select write, msg
