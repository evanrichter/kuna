/* gcc 16.2: gcc -m32 -std=c11 -O1 -fno-ident -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -fPIC -shared -Wl,--build-id=none -Wl,--hash-style=gnu -Wl,-soname,libwire.so -o libwire_i386.so libwire.c
 *
 * The 32-bit build of libwire_x86_64.so: cdecl passes every parameter on the
 * stack, for retyping a parameter by its stack slot
 * (kuna-console/tests/verify_inputtypes.rs). The binary was built from wire.h
 * and libwire.c; both are reproduced here as one file. */
#include <stddef.h>
#include <stdint.h>

#define WIRE_MAX_ATTEMPTS 3

struct Request {
    uint32_t kind;
    void *payload;
    uint32_t length;
    uint16_t flags;
    uint16_t attempts;
    int32_t status;
};

void init_request(struct Request *req, uint32_t kind, void *payload, uint32_t length);
int send_request(struct Request *req);
uint32_t kind_weight(uint32_t kind);
/* Library-local Header. client.c defines a different struct Header. */
struct Header {
    uint32_t magic;
    uint32_t length;
    uint16_t checksum;
    uint16_t kind;
};

/* The "wire": volatile globals, so the compiler keeps every store and load. */
volatile struct Header wire_last_header;
volatile uint32_t wire_fail_budget = 1;

__attribute__((noinline)) static uint16_t checksum(const uint8_t *bytes, uint32_t length)
{
    uint16_t sum = 0;
    for (uint32_t i = 0; i < length; i++)
        sum = (uint16_t)(sum * 31 + bytes[i]);
    return sum;
}

__attribute__((noinline)) static int transmit(const struct Request *req)
{
    struct Header header;
    header.magic = 0x57495245; /* "WIRE" */
    header.length = req->length;
    header.checksum = checksum(req->payload, req->length);
    header.kind = (uint16_t)req->kind;
    wire_last_header = header;
    if (wire_fail_budget > 0) {
        wire_fail_budget--;
        return -1;
    }
    return header.checksum;
}

__attribute__((noinline)) void init_request(struct Request *req, uint32_t kind, void *payload,
                                            uint32_t length)
{
    req->kind = kind;
    req->payload = payload;
    req->length = length;
    req->flags = 0;
    req->attempts = 0;
    req->status = 0;
}

/* The guard skips the retry loop when there is no payload, then rejoins at
 * cleanup. */
__attribute__((noinline)) int send_request(struct Request *req)
{
    int rc = -1;
    if (req->payload == NULL)
        goto cleanup;
retry:
    rc = transmit(req);
    if (rc < 0 && ++req->attempts < WIRE_MAX_ATTEMPTS)
        goto retry;
cleanup:
    req->status = rc;
    return rc;
}

/* One multiply reads kind twice: a target for occurrence-level anchors. */
__attribute__((noinline)) uint32_t kind_weight(uint32_t kind)
{
    return kind * kind;
}
