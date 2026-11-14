// Minimal stand-in for the Open Enclave enclave headers used by the tests.
#ifndef _TEST_OE_ENCLAVE_H
#define _TEST_OE_ENCLAVE_H

typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef int oe_result_t;
typedef long oe_host_fd_t;
typedef struct { uint8_t buf[16]; } sgx_key_t;
typedef struct { uint8_t buf[512]; } sgx_key_request_t;
typedef int oe_spinlock_t;

#define OE_OK 0
#define NULL ((void*)0)

void* memcpy(void* dst, const void* src, size_t n);
void* memset(void* dst, int c, size_t n);
int memcmp(const void* a, const void* b, size_t n);

int oe_is_outside_enclave(const void* p, size_t n);
int oe_is_within_enclave(const void* p, size_t n);
void* oe_host_malloc(size_t size);
void oe_host_free(void* p);
void* oe_malloc(size_t size);
void oe_free(void* p);
void oe_memcpy_aligned(void* dst, const void* src, size_t n);
void* oe_memcpy_with_barrier(void* dst, const void* src, size_t n);
void oe_secure_zero_fill(volatile void* p, size_t n);
int oe_constant_time_mem_equal(const void* a, const void* b, size_t n);
oe_result_t oe_get_key(const sgx_key_request_t* request, sgx_key_t* key);
int oe_host_printf(const char* fmt, ...);
oe_result_t oe_spin_lock(oe_spinlock_t* l);
oe_result_t oe_spin_unlock(oe_spinlock_t* l);
void oe_abort(void);
#define oe_lfence() __builtin_ia32_lfence()

oe_result_t oe_syscall_read_ocall(
    ssize_t* _retval, oe_host_fd_t fd, void* buf, size_t count);

#endif
