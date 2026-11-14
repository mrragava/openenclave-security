// Enclave-side patterns for the Open Enclave SGX queries. Each BAD case
// mirrors a defect class found in the Open Enclave SDK; GOOD cases are the
// corrected forms and must not be reported.
#include "openenclave/enclave.h"

/* ---- [user_check] host pointers (HostPointerUnvalidatedDeref) ---------- */

struct ctx
{
    uint64_t counter;
    uint32_t flag;
    uint32_t pad;
    uint64_t value;
};

void set_counter(struct ctx* c)
{
    c->counter = 1; // BAD: host pointer dereferenced unchecked
}

void set_counter_checked(struct ctx* c)
{
    if (!oe_is_outside_enclave(c, sizeof(*c)))
        return;
    c->counter = 1; // GOOD
}

typedef struct
{
    struct ctx* c;
    oe_result_t oe_result;
} set_counter_args_t;

static void ecall_set_counter(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    set_counter_args_t* _pargs_in = (set_counter_args_t*)input_buffer;
    set_counter(_pargs_in->c);
}

static void ecall_set_counter_checked(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    set_counter_args_t* _pargs_in = (set_counter_args_t*)input_buffer;
    set_counter_checked(_pargs_in->c);
}

/* ---- Iago: OCALL results used as sizes (IagoUncheckedOcallOutput) ------- */

ssize_t read_into(uint8_t* dst, uint8_t* tmp, size_t count)
{
    ssize_t ret = -1;
    if (oe_syscall_read_ocall(&ret, 3, tmp, count) != OE_OK)
        return -1;
    memcpy(dst, tmp, (size_t)ret); // BAD: host-chosen length
    return ret;
}

ssize_t read_into_checked(uint8_t* dst, uint8_t* tmp, size_t count)
{
    ssize_t ret = -1;
    if (oe_syscall_read_ocall(&ret, 3, tmp, count) != OE_OK)
        return -1;
    if (ret < 0 || ret > (ssize_t)count)
        return -1;
    memcpy(dst, tmp, (size_t)ret); // GOOD
    return ret;
}

/* ---- Host memory accesses (double fetch, MMIO stale data, AEPIC) ------- */

#define MAX_LEN 64

void double_fetch(uint8_t* dst)
{
    struct ctx* h = (struct ctx*)oe_host_malloc(sizeof(struct ctx));
    if (h->value > MAX_LEN)
        return;
    memcpy(dst, "x", h->value); // BAD: re-read after the check
}

void single_fetch(uint8_t* dst)
{
    struct ctx* h = (struct ctx*)oe_host_malloc(sizeof(struct ctx));
    uint64_t len = h->value;
    if (len > MAX_LEN)
        return;
    memcpy(dst, "x", len); // GOOD
}

void host_writes(struct ctx* local)
{
    struct ctx* s = (struct ctx*)oe_host_malloc(sizeof(struct ctx));
    s->flag = 1;                                   // BAD: 4-byte store
    s->value = 2;                                  // GOOD: aligned 8-byte store
    memcpy(s, local, sizeof(*s));                  // BAD: byte-wise copy out
    oe_memcpy_with_barrier(s, local, sizeof(*s));  // GOOD
}

uint64_t host_reads(struct ctx* local)
{
    struct ctx* s = (struct ctx*)oe_host_malloc(sizeof(struct ctx));
    uint32_t f = s->flag;                     // BAD: 4-byte load
    uint64_t v = s->value;                    // GOOD
    memcpy(local, s, sizeof(*s));             // BAD: byte-wise copy in
    oe_memcpy_aligned(local, s, sizeof(*s));  // GOOD
    return f + v;
}

/* ---- Spectre v1 on an ECALL index (SpectreV1IndexedLoad) -------------- */

typedef void (*handler_t)(void);
handler_t handlers[4];

void dispatch(uint32_t id)
{
    if (id >= 4)
        return;
    handler_t h = handlers[id]; // BAD: no lfence between check and load
    h();
}

void dispatch_fenced(uint32_t id)
{
    if (id >= 4)
        return;
    oe_lfence();
    handler_t h = handlers[id]; // GOOD
    h();
}

typedef struct
{
    uint32_t id;
    oe_result_t oe_result;
} dispatch_args_t;

static void ecall_dispatch(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    dispatch_args_t* _pargs_in = (dispatch_args_t*)input_buffer;
    dispatch(_pargs_in->id);
    dispatch_fenced(_pargs_in->id);
}

/* ---- Unsigned underflow of untrusted sizes (UntrustedUnsignedUnderflow) */

void decode(uint8_t* out, const uint8_t* hex, size_t size)
{
    for (size_t i = 0; i < size - 1; i += 2) // BAD: wraps when size == 0
        out[i / 2] = hex[i];
}

void decode_checked(uint8_t* out, const uint8_t* hex, size_t size)
{
    if (size < 2)
        return;
    for (size_t i = 0; i < size - 1; i += 2) // GOOD
        out[i / 2] = hex[i];
}

typedef struct
{
    uint8_t* out;
    const uint8_t* hex;
    size_t size;
    oe_result_t oe_result;
} decode_args_t;

static void ecall_decode(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    decode_args_t* _pargs_in = (decode_args_t*)input_buffer;
    _pargs_in->out = output_buffer;
    _pargs_in->hex = input_buffer;
    decode(_pargs_in->out, _pargs_in->hex, _pargs_in->size);
    decode_checked(_pargs_in->out, _pargs_in->hex, _pargs_in->size);
}

/* ---- Locks (LockNotReleased, DoubleUnlock, LockHeldAcrossOcall) -------- */

static oe_spinlock_t _lock;
static int _state;

oe_result_t leak_on_error(int err)
{
    oe_result_t result = OE_OK;
    oe_spin_lock(&_lock); // BAD: `goto done` skips the unlock
    if (err)
    {
        result = 1;
        goto done;
    }
    _state = 1;
    oe_spin_unlock(&_lock);
done:
    return result;
}

oe_result_t flag_pattern(int err)
{
    oe_result_t result = OE_OK;
    int locked = 0;
    oe_spin_lock(&_lock); // GOOD: released through the flag
    locked = 1;
    if (err)
    {
        result = 1;
        goto done;
    }
    _state = 1;
done:
    if (locked)
        oe_spin_unlock(&_lock);
    return result;
}

oe_result_t acquire_may_fail(void)
{
    if (oe_spin_lock(&_lock) != OE_OK) // GOOD: failure path holds nothing
        return 1;
    _state = 2;
    oe_spin_unlock(&_lock);
    return OE_OK;
}

oe_result_t double_unlock(int err)
{
    oe_result_t result = OE_OK;
    char* report = oe_malloc(16);
    if (!report)
        goto done; // jumps to an unlock without holding the lock
    oe_spin_lock(&_lock);
    _state = 3;
    oe_spin_unlock(&_lock);
    report[0] = 0;
done:
    oe_spin_unlock(&_lock); // BAD: second release / release without acquire
    return result;
}

void print_under_lock(void)
{
    oe_spin_lock(&_lock);
    oe_host_printf("state=%d\n", _state); // BAD: OCALL while holding the lock
    oe_spin_unlock(&_lock);
}

/* ---- Secrets (SecretNotZeroized, NonConstantTimeSecretCompare, SecretToHost) */

int derive_and_drop(const sgx_key_request_t* req)
{
    sgx_key_t key;
    if (oe_get_key(req, &key) != OE_OK) // BAD: key left on the stack
        return -1;
    return key.buf[0];
}

int derive_and_memset(const sgx_key_request_t* req)
{
    sgx_key_t key;
    int r;
    oe_get_key(req, &key); // BAD: memset may be elided
    r = key.buf[0];
    memset(&key, 0, sizeof(key));
    return r;
}

int derive_and_wipe(const sgx_key_request_t* req)
{
    sgx_key_t key;
    int r;
    oe_get_key(req, &key); // GOOD
    r = key.buf[0];
    oe_secure_zero_fill(&key, sizeof(key));
    return r;
}

int check_mac(const sgx_key_request_t* req, const uint8_t* expected)
{
    sgx_key_t key;
    int ok;
    oe_get_key(req, &key);
    ok = memcmp(&key, expected, sizeof(key)) == 0; // BAD: variable time
    ok &= oe_constant_time_mem_equal(&key, expected, sizeof(key)); // GOOD
    oe_secure_zero_fill(&key, sizeof(key));
    return ok;
}

void leak_key(const sgx_key_request_t* req)
{
    sgx_key_t key;
    oe_get_key(req, &key);
    oe_host_printf("%s", (const char*)key.buf); // BAD: secret to host
    oe_secure_zero_fill(&key, sizeof(key));
}

/* ---- Lookup with inverted memcmp (InvertedMemcmpLookup) --------------- */

typedef struct
{
    uint8_t id[16];
} plugin_t;

plugin_t* plugins[8];
int num_plugins;

plugin_t* find_plugin(const uint8_t* id)
{
    for (int i = 0; i < num_plugins; i++)
        if (memcmp(plugins[i]->id, id, 16)) // BAD: returns first mismatch
            return plugins[i];
    return NULL;
}

plugin_t* find_plugin_fixed(const uint8_t* id)
{
    for (int i = 0; i < num_plugins; i++)
        if (memcmp(plugins[i]->id, id, 16) == 0) // GOOD
            return plugins[i];
    return NULL;
}
