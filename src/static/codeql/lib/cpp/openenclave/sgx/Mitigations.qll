/**
 * Provides models of the software mitigations Open Enclave uses against
 * transient-execution and stale-data hardware vulnerabilities, and of the
 * secret-hygiene primitives.
 */

import cpp

/** An `lfence` speculation barrier (`oe_lfence()`, `_mm_lfence()`, ...). */
class SpeculationBarrier extends Expr {
  SpeculationBarrier() {
    this.(FunctionCall).getTarget().getName() =
      ["__builtin_ia32_lfence", "_mm_lfence", "oe_lfence", "__builtin_speculation_safe_value"]
    or
    exists(MacroInvocation mi | mi.getMacroName() = "oe_lfence" and mi.getExpr() = this)
  }
}

/**
 * A function performing an MMIO-stale-data hardened write to host memory
 * (`verw` + fences around writes that are not 8-byte aligned and sized).
 */
class BarrierWriteFunction extends Function {
  BarrierWriteFunction() {
    this.getName() =
      [
        "oe_memcpy_with_barrier", "oe_memmove_with_barrier", "oe_memset_with_barrier",
        "oe_memcpy_s_with_barrier", "oe_memmove_s_with_barrier", "oe_memset_s_with_barrier",
        "_memcpy_unaligned_with_barrier", "_memset_unaligned_with_barrier",
        "_memmove_with_barrier", "_memset_aligned"
      ]
  }
}

/** Holds if `e` is produced by an expansion of `OE_WRITE_VALUE_WITH_BARRIER`. */
predicate isInBarrierWriteMacro(Element e) {
  exists(MacroInvocation mi |
    mi.getMacroName() = "OE_WRITE_VALUE_WITH_BARRIER" and mi.getAnExpandedElement() = e
  )
}

/** `oe_memcpy_aligned`: copies with 8-byte loads and stores (`rep movsq`). */
class AlignedCopyFunction extends Function {
  AlignedCopyFunction() { this.hasName("oe_memcpy_aligned") }
}

/** A function that compares memory in constant time. */
class ConstantTimeCompareFunction extends Function {
  ConstantTimeCompareFunction() {
    this.getName() =
      [
        "oe_constant_time_mem_equal", "oe_secure_aes_cmac_equal", "CRYPTO_memcmp",
        "mbedtls_ct_memcmp", "mbedtls_ssl_safer_memcmp", "timingsafe_bcmp", "consttime_memequal"
      ]
  }
}

/** A function that erases memory in a way the compiler may not elide. */
class SecureZeroFunction extends Function {
  SecureZeroFunction() {
    this.getName() =
      [
        "oe_secure_zero_fill", "mbedtls_platform_zeroize", "OPENSSL_cleanse", "explicit_bzero",
        "memset_s", "SecureZeroMemory", "RtlSecureZeroMemory", "oe_free_key", "oe_free_seal_key"
      ]
  }
}

/** A call that does not return to its caller. */
class NonReturningCall extends FunctionCall {
  NonReturningCall() {
    this.getTarget().getName().regexpMatch(".*abort.*|_?_?exit|_Exit|__assert_fail|oe_panic")
    or
    this.getTarget().getAnAttribute().hasName("noreturn")
  }
}
