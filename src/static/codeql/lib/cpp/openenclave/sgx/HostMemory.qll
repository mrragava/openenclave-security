/**
 * Provides classes for reasoning about accesses that enclave code makes to
 * untrusted host memory. The hardware-hygiene rules (ÆPIC Leak, MMIO stale
 * data) and the double-fetch rule are expressed over these accesses.
 *
 * Host pointer bases are assumed to be 8-byte aligned: Open Enclave enforces
 * this for its own buffers (`OE_EDGER8R_BUFFER_ALIGNMENT`, `% 8` checks).
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import TrustBoundary
import Mitigations

/** A call returning a pointer into host memory. */
class HostAllocationCall extends FunctionCall {
  HostAllocationCall() {
    this.getTarget().getName() =
      [
        "oe_host_malloc", "oe_host_calloc", "oe_host_realloc", "oe_host_strndup",
        "oe_allocate_ocall_buffer", "oe_allocate_switchless_ocall_buffer", "oe_arena_malloc",
        "oe_arena_calloc", "oe_allocate_arena", "oe_ecall_context_get_ocall_buffer",
        "oe_ecall_context_get_ocall_args"
      ]
  }
}

/** A thread-data field holding a host pointer that was validated at enclave entry. */
class ValidatedHostPointerField extends Field {
  ValidatedHostPointerField() {
    this.getName() = ["host_ecall_context", "host_previous_ecall_context"]
  }
}

/** A call to a C library or Open Enclave memory/string function. */
class MemoryFunctionCall extends FunctionCall {
  string name;

  MemoryFunctionCall() {
    name = this.getTarget().getName().regexpReplaceAll("^oe_", "") and
    name =
      [
        "memcpy", "memmove", "memset", "memcmp", "strcpy", "strncpy", "strcat", "strncat",
        "strlen", "strnlen", "strcmp", "strncmp", "strlcpy", "strlcat", "sprintf", "snprintf",
        "vsnprintf", "memcpy_s", "memmove_s", "memset_s", "memcpy_aligned",
        "memcpy_with_barrier", "memmove_with_barrier", "memset_with_barrier",
        "memcpy_s_with_barrier", "memmove_s_with_barrier", "memset_s_with_barrier"
      ]
  }

  /** Gets the argument designating memory written by the call. */
  Expr getDestination() {
    name.regexpMatch("mem(cpy|move|set).*|str(n?cpy|n?cat|lcpy|lcat)|v?s?n?printf") and
    result = this.getArgument(0)
  }

  /** Gets an argument designating memory read by the call. */
  Expr getASource() {
    name.regexpMatch("(memcpy|memmove)(_aligned|_with_barrier)?|str(n?cpy|n?cat|lcpy|lcat)") and
    result = this.getArgument(1)
    or
    name.regexpMatch("(memcpy|memmove)_s(_with_barrier)?") and result = this.getArgument(2)
    or
    name.regexpMatch("memcmp|strn?cmp") and result = this.getArgument([0, 1])
    or
    name.regexpMatch("strn?len") and result = this.getArgument(0)
  }

  /** Gets the argument giving the number of bytes accessed, if any. */
  Expr getSizeArgument() {
    name.regexpMatch("(memcpy|memmove)(_aligned|_with_barrier)?|memset(_with_barrier)?|memcmp|strncpy|strncat|strncmp|strlcpy|strlcat") and
    result = this.getArgument(2)
    or
    name = "strnlen" and result = this.getArgument(1)
    or
    name.regexpMatch("(memcpy|memmove|memset)_s(_with_barrier)?") and result = this.getArgument(3)
    or
    name = ["snprintf", "vsnprintf"] and result = this.getArgument(1)
  }

  /** Holds if writes by this call are hardened against MMIO stale data. */
  predicate isBarrierWrite() { this.getTarget() instanceof BarrierWriteFunction }

  /** Holds if this call accesses memory only with 8-byte aligned loads and stores. */
  predicate isEightByteGranular() { this.getTarget() instanceof AlignedCopyFunction }
}

/** Holds if `e` is the base address of a memory access or memory-function argument. */
predicate isAccessBase(Expr e) {
  e = any(PointerFieldAccess fa).getQualifier()
  or
  e = any(PointerDereferenceExpr d).getOperand()
  or
  exists(ArrayExpr ae | e = ae.getArrayBase() and e.getUnspecifiedType() instanceof PointerType)
  or
  e = any(MemoryFunctionCall c).getDestination()
  or
  e = any(MemoryFunctionCall c).getASource()
}

/** A step that derives a pointer into the same object: `p + n`, `&p->f`, `&p[i]`, `p->array`. */
predicate pointerDerivationStep(Expr a, Expr b) {
  a.getUnspecifiedType() instanceof PointerType and
  (
    b.(PointerAddExpr).getAnOperand().getUnconverted() = a
    or
    b.(PointerSubExpr).getLeftOperand().getUnconverted() = a
    or
    exists(Expr operand | operand = b.(AddressOfExpr).getOperand() |
      operand.(PointerFieldAccess).getQualifier().getUnconverted() = a or
      operand.(ArrayExpr).getArrayBase().getUnconverted() = a
    )
    or
    b.(PointerFieldAccess).getQualifier().getUnconverted() = a and
    b.getUnspecifiedType() instanceof ArrayType
  )
}

private module HostMemoryPointerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n instanceof HostChosenPointer
    or
    n.asExpr() instanceof HostAllocationCall
    or
    n.asExpr().(FieldAccess).getTarget() instanceof ValidatedHostPointerField
  }

  predicate isSink(DataFlow::Node n) {
    exists(Expr e | isAccessBase(e) and n.asExpr() = e.getUnconverted())
  }

  predicate isBarrier(DataFlow::Node n) {
    // The memory primitives are analyzed at their call sites.
    n.getFunction() instanceof BarrierWriteFunction
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    pointerDerivationStep(a.asExpr(), b.asExpr())
  }
}

/** Tracks pointers into host memory to the expressions that dereference them. */
module HostMemoryPointerFlow = DataFlow::Global<HostMemoryPointerConfig>;

/** Holds if `e` is a pointer into host memory used as an access base. */
predicate pointsToHostMemory(Expr e) {
  isAccessBase(e) and HostMemoryPointerFlow::flowToExpr(e.getUnconverted())
}

/**
 * A taint step for data brought into the enclave from host memory: copying out
 * of host memory yields host-controlled data, and so do fields later read from
 * the destination struct.
 */
predicate hostDataCopyStep(DataFlow::Node a, DataFlow::Node b) {
  exists(MemoryFunctionCall c |
    pointsToHostMemory(c.getASource()) and
    a.asExpr() = c.getASource().getUnconverted() and
    b.asDefiningArgument() = c.getDestination()
  )
  or
  exists(Variable v |
    a.asDefiningArgument().(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v and
    b.asExpr().(DotFieldAccess).getQualifier().(VariableAccess).getTarget() = v
  )
}

/** Holds if `e` designates a location (lvalue) in host memory. */
predicate isHostLocation(Expr e) {
  pointsToHostMemory(e.(PointerFieldAccess).getQualifier())
  or
  pointsToHostMemory(e.(PointerDereferenceExpr).getOperand())
  or
  pointsToHostMemory(e.(ArrayExpr).getArrayBase())
  or
  isHostLocation(e.(DotFieldAccess).getQualifier())
  or
  exists(Expr base | base = e.(ArrayExpr).getArrayBase() |
    base.getUnspecifiedType() instanceof ArrayType and isHostLocation(base)
  )
}

/** Holds if the location designated by `e` is 8-byte aligned, assuming an aligned host base. */
private predicate isEightByteAligned(Expr e) {
  e.(PointerFieldAccess).getTarget().getByteOffset() % 8 = 0
  or
  e instanceof PointerDereferenceExpr
  or
  e.(ArrayExpr).getArrayBase().getUnspecifiedType() instanceof PointerType and
  e.getUnspecifiedType().getSize() % 8 = 0
  or
  isEightByteAligned(e.(DotFieldAccess).getQualifier()) and
  e.(DotFieldAccess).getTarget().getByteOffset() % 8 = 0
  or
  exists(Expr base | base = e.(ArrayExpr).getArrayBase() |
    base.getUnspecifiedType() instanceof ArrayType and
    isEightByteAligned(base) and
    e.getUnspecifiedType().getSize() % 8 = 0
  )
}

/** A load or store of host memory, at the granularity the program accesses it. */
class HostMemoryAccess extends Expr {
  HostMemoryAccess() {
    isHostLocation(this) and
    isEnclaveCode(this) and
    not exists(DotFieldAccess outer | outer.getQualifier() = this) and
    not this.getUnspecifiedType() instanceof ArrayType and
    not this.getParent() instanceof AddressOfExpr and
    not exists(SizeofOperator s | s.getAChild*() = this) and
    not this.getEnclosingFunction() instanceof BarrierWriteFunction and
    not isInBarrierWriteMacro(this)
  }

  /** Gets the number of bytes accessed. */
  int getAccessSize() { result = this.getUnspecifiedType().getSize() }

  /** Holds if this access is an 8-byte aligned access of a multiple of 8 bytes. */
  predicate isEightByteGranular() {
    this.getAccessSize() % 8 = 0 and isEightByteAligned(this)
  }

  /** Holds if this expression is written. */
  predicate isWrite() {
    this = any(Assignment a).getLValue() or this = any(CrementOperation c).getOperand()
  }

  /** Holds if this expression is read. */
  predicate isRead() { not this = any(AssignExpr a).getLValue() }
}
