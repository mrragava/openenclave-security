/**
 * @name Lock released twice or without being held
 * @description A lock is released again without being re-acquired, or released on a
 *              path that never acquired it. Open Enclave spinlocks have no owner check,
 *              so the extra release frees a lock that another thread now holds and
 *              breaks mutual exclusion.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @precision high
 * @id oe/sgx/double-unlock
 * @tags reliability
 *       security
 *       sgx
 *       external/cwe/cwe-765
 */

import cpp
import openenclave.sgx.Sgx

from LockRelease rel, string msg, Element other, string otherMsg
where
  exists(LockRelease first |
    releasedAt(first, rel) and
    sameLock(first.getLock(), rel.getLock()) and
    other = first and
    msg = "This lock may already have been released $@." and
    otherMsg = "here"
  )
  or
  releasedWithoutAcquire(rel) and
  other = rel.getEnclosingFunction() and
  msg = "This lock may be released on a path where $@ never acquired it." and
  otherMsg = rel.getEnclosingFunction().getName()
select rel, msg, other, otherMsg
