#pragma once
#include <stdint.h>
#include <stddef.h>

#define LUMICORE_ABI_VERSION 3

/* Core dispatcher ABI. These layouts mirror Rust #[repr(C)] structs. */
typedef struct {
    uint16_t abi_version;
    uint16_t op_code;
    uint32_t flags;
    uint64_t trace_id_hi;
    uint64_t trace_id_lo;
    size_t input_len;
    size_t output_cap;
} FfiEnvelope;

typedef struct {
    int32_t code;
    size_t output_len;
    uint16_t error_code;
    uint16_t reserved;
} FfiStatus;

typedef struct {
    uint64_t stream_id;
    uint64_t reserved;
} StreamHandle;

enum {
    LUMICORE_STREAM_EVT_PROBE_RESULT = 1,
    LUMICORE_STREAM_EVT_POOL_UPDATE = 2,
    LUMICORE_STREAM_EVT_SCAN_DONE = 3,
    LUMICORE_STREAM_EVT_ERROR = 255,
};

typedef void (*StreamCallback)(uint16_t event_type, const uint8_t* data,
                               size_t data_len, void* user_data);
typedef void (*CoreAsyncCallback)(uint64_t req_id, char* result_json);

/* Go-private bridge exports consumed by active CGO adapter files. */
void call_core_async_ffi(const char* endpoint, const char* input_json,
                         uint64_t req_id, CoreAsyncCallback cb);
char* scan_icmp_ffi(const char* input_json);
char* scan_ports_ffi(const char* input_json);
char* probe_tls_ffi(const char* input_json);
char* detect_sni_ffi(const char* input_json);
char* test_speed_ffi(const char* input_json);
char* probe_wg_ffi(const char* input_json);
char* inject_fake_packet_ffi(const char* input_json);
void free_string(char* ptr);
char* disassemble_shellcode_ffi(const char* input_json);

FfiStatus lumicore_call(const FfiEnvelope* env, const uint8_t* input, uint8_t* output);
uint64_t lumicore_version(uint16_t minimum_required_major);
size_t lumicore_version_string(uint8_t* buf, size_t buf_len);
StreamHandle lumicore_stream_start(uint16_t op, const uint8_t* input, size_t input_len,
                                   StreamCallback cb, void* user_data);
void lumicore_stream_cancel(StreamHandle handle);
