// Struct members of the system EDLs, modeled by edl2codeql.py as Field access
// paths of the generated oe-system-edl model (CodeQL does not conflate a
// struct with its members). The declarations match the oeedger8r output.
#include "openenclave/enclave.h"

typedef long oe_off_t;
typedef unsigned short oe_sa_family_t;

typedef struct oe_stat_t
{
    oe_off_t st_size;
} oe_stat_t;

typedef struct oe_asymmetric_key_params_t
{
    int type;
    int format;
    void* user_data;
    size_t user_data_size;
} oe_asymmetric_key_params_t;

struct oe_sockaddr
{
    oe_sa_family_t sa_family;
    char sa_data[14];
};

oe_result_t oe_syscall_fstat_ocall(int* _retval, oe_host_fd_t fd, struct oe_stat_t* buf);
oe_result_t oe_syscall_connect_ocall(
    int* _retval, oe_host_fd_t sockfd, const struct oe_sockaddr* addr, uint32_t addrlen);
void oe_secure_zero_fill(volatile void* p, size_t n);

/* ---- [out] struct member of an OCALL (IagoUncheckedOcallOutput) -------- */

int load_file(uint8_t* dst, const uint8_t* src, oe_host_fd_t fd, struct oe_stat_t* st)
{
    int ret;
    if (oe_syscall_fstat_ocall(&ret, fd, st) != OE_OK || ret != 0)
        return -1;
    memcpy(dst, src, (size_t)st->st_size); // BAD: file size chosen by the host
    return 0;
}

int load_file_checked(
    uint8_t* dst, size_t cap, const uint8_t* src, oe_host_fd_t fd, struct oe_stat_t* st)
{
    int ret;
    oe_off_t size;
    if (oe_syscall_fstat_ocall(&ret, fd, st) != OE_OK || ret != 0)
        return -1;
    size = st->st_size;
    if (size < 0 || (size_t)size > cap)
        return -1;
    memcpy(dst, src, (size_t)size); // GOOD
    return 0;
}

/* ---- [in] struct member of an ECALL (UntrustedUnsignedUnderflow) ------- */

oe_result_t oe_get_public_key_ecall(
    const oe_asymmetric_key_params_t* key_params,
    const void* key_info,
    size_t key_info_size,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out)
{
    const uint8_t* data = (const uint8_t*)key_params->user_data;
    uint8_t* out = (uint8_t*)key_buffer;
    for (size_t i = 0; i < key_params->user_data_size - 1; i++) // BAD: wraps at 0
        out[i] = data[i];
    return OE_OK;
}

/* ---- Secret stored in an [in] struct of an OCALL (SecretToHost) -------- */

void connect_with_key(const sgx_key_request_t* req, oe_host_fd_t fd)
{
    sgx_key_t key;
    struct oe_sockaddr addr;
    int ret;
    oe_get_key(req, &key);
    addr.sa_family = key.buf[0]; // BAD: key byte sent to the host
    oe_syscall_connect_ocall(&ret, fd, &addr, sizeof(addr));
    oe_secure_zero_fill(&key, sizeof(key));
}

void connect_plain(oe_host_fd_t fd)
{
    struct oe_sockaddr addr;
    int ret;
    addr.sa_family = 2; // GOOD
    oe_syscall_connect_ocall(&ret, fd, &addr, sizeof(addr));
}
