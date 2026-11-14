/**
 * @name Lock not released on all paths
 * @description A lock acquired in this function is released on some paths but still
 *              held when the function returns on others, typically through an
 *              OE_CHECK/OE_RAISE `goto done` that jumps past the unlock. Every later
 *              acquirer spins forever.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision high
 * @id oe/sgx/lock-not-released
 * @tags reliability
 *       security
 *       sgx
 *       external/cwe/cwe-667
 *       external/cwe/cwe-764
 */

import cpp
import openenclave.sgx.Sgx

from LockAcquire acq, Function f
where
  f = acq.getEnclosingFunction() and
  heldAt(acq, f) and
  exists(LockRelease rel | rel.getEnclosingFunction() = f and sameLock(rel.getLock(), acq.getLock()))
select acq, "This lock can still be held when '" + f.getName() + "' returns."
