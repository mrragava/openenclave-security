/**
 * @name memcmp result used as a match in a lookup loop
 * @description In a loop that returns the matching element, `if (memcmp(a, b, n))`
 *              is true when the buffers differ, so the loop returns the first element
 *              that does NOT match. In enclave code this selects the wrong plugin, key
 *              or policy (for example a sealing plugin chosen by ID).
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id oe/sgx/inverted-memcmp-lookup
 * @tags correctness
 *       security
 *       external/cwe/cwe-697
 */

import cpp

from IfStmt ifs, FunctionCall cmp, ReturnStmt ret, Loop loop
where
  cmp.getTarget().getName() = ["memcmp", "oe_memcmp", "strcmp", "oe_strcmp", "strncmp", "oe_strncmp", "bcmp"] and
  ifs.getCondition().getUnconverted() = cmp and
  (ret = ifs.getThen() or ret = ifs.getThen().(BlockStmt).getStmt(0)) and
  ret.getExpr().getUnconverted().getUnspecifiedType() instanceof PointerType and
  not ret.getExpr().getValue() = "0" and
  loop.getStmt().getAChild*() = ifs
select cmp,
  "'" + cmp.getTarget().getName() +
    "' is non-zero when the buffers differ, so this lookup returns a non-matching element."
