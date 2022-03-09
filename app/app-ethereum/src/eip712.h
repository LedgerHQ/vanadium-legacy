#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

#define DIGEST_SIZE 32

typedef enum {
    TYPE_BYTES1,
    TYPE_BYTES32,
    TYPE_UINT8,
    TYPE_UINT256,
    TYPE_INT8,
    TYPE_INT256,
    TYPE_BOOL,
    TYPE_ADDRESS,
    TYPE_BYTES,
    TYPE_STRING,
    TYPE_ARRAY,
    TYPE_STRUCT,
} member_type_e;

struct member_data_s;

typedef struct hash_struct_s {
    uint8_t type_hash[DIGEST_SIZE];
    size_t count;
    struct member_data_s *members;
} hash_struct_t;

typedef struct eip712_address_s {
    char value[40];
} eip712_address_t;

typedef struct eip712_string_s {
    const char *value;
    size_t length;
} eip712_string_t;

typedef struct eip712_bytes_s {
    const uint8_t *value;
    size_t size;
} eip712_bytes_t;

typedef struct member_data_s {
    member_type_e type;
    char *display;
    union {
        bool boolean;
        eip712_bytes_t bytes;
        eip712_string_t string;
        hash_struct_t *hstruct;
        eip712_address_t address;
    };
} member_data_t;

typedef enum {
    FIELD_KEY,
    FIELD_VALUE,
    FIELD_OTHER,
} json_field_e;

typedef struct json_field_s {
    json_field_e type;
    union {
        char *key;
        member_data_t *value;
        bool other;
    };
} json_field_t;

bool set_value(member_data_t *member, const char *value, const size_t size);
void copy_string(char *dst, size_t size, eip712_string_t *string);
void copy_address(char *dst, size_t size, eip712_address_t *address);

struct jsmntok;
typedef struct jsmntok jsmntok_t;

const hash_struct_t *eip712_example_mail(const char *json_string, jsmntok_t *t, int token_count);
const char *eip712_hash_struct(const char *json_string,
                               size_t size,
                               const uint8_t *domain,
                               uint8_t *digest);
bool extract_fields(json_field_t *fields,
                    const char *json_string,
                    const jsmntok_t *t,
                    const int token_count);