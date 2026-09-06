/**
 * LumiNet Lumicore Native C SDK Header
 *
 * Universal embeddable C/C++ interface for third-party crawlers, browsers,
 * and external network tools to consume LumiNet's DPI evasion and scanning core.
 */

#ifndef LUMICORE_SDK_H
#define LUMICORE_SDK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define LUMICORE_SDK_VERSION_MAJOR 1
#define LUMICORE_SDK_VERSION_MINOR 0
#define LUMICORE_ABI_VERSION 3

/* Envelopes and Return Status */
typedef struct {
    uint16_t abi_version;
    uint16_t op_code;
    uint32_t flags;
    uint64_t trace_id_hi;
    uint64_t trace_id_lo;
    size_t input_len;
    size_t output_cap;
} LumicoreEnvelope;

typedef struct {
    int32_t code;
    size_t output_len;
    uint16_t error_code;
    uint16_t reserved;
} LumicoreStatus;

typedef struct {
    uint64_t stream_id;
    uint64_t reserved;
} LumicoreStreamHandle;

/* Stream Event Types */
enum LumicoreStreamEventType {
    LUMICORE_EVT_PROBE_RESULT = 1,
    LUMICORE_EVT_POOL_UPDATE  = 2,
    LUMICORE_EVT_SCAN_DONE    = 3,
    LUMICORE_EVT_ERROR        = 255,
};

typedef void (*LumicoreStreamCallback)(uint16_t event_type, const uint8_t* data,
                                       size_t data_len, void* user_data);
typedef void (*LumicoreAsyncCallback)(uint64_t req_id, char* result_json);

/* Core SDK API Declarations */
uint64_t lumicore_version(uint16_t minimum_required_major);
size_t lumicore_version_string(uint8_t* buf, size_t buf_len);

LumicoreStatus lumicore_call(const LumicoreEnvelope* env, const uint8_t* input, uint8_t* output);

LumicoreStreamHandle lumicore_stream_start(uint16_t op, const uint8_t* input, size_t input_len,
                                           LumicoreStreamCallback cb, void* user_data);
void lumicore_stream_cancel(LumicoreStreamHandle handle);

/* Direct High-Level JSON Scanning & Evasion Exports */
char* scan_icmp_ffi(const char* input_json);
char* scan_ports_ffi(const char* input_json);
char* probe_tls_ffi(const char* input_json);
char* detect_sni_ffi(const char* input_json);
char* test_speed_ffi(const char* input_json);
char* probe_wg_ffi(const char* input_json);
char* inject_fake_packet_ffi(const char* input_json);
void free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* LUMICORE_SDK_H */
