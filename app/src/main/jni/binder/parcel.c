#include "parcel.h"
#include <android/api-level.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PARCEL_MAX_ALLOC (64 * 1024)

void parcel_init(ParcelBuilder* builder) {
    if (builder) {
        builder->buf = NULL;
        builder->size = 0;
        builder->cap = 0;
    }
}

void parcel_free(ParcelBuilder* builder) {
    if (builder && builder->buf) {
        memset(builder->buf, 0, builder->cap);
        free(builder->buf);
        builder->buf = NULL;
        builder->size = 0;
        builder->cap = 0;
    }
}

static int parcel_ensure(ParcelBuilder* builder, size_t more) {
    if (!builder) return -1;
    if (builder->size + more <= builder->cap) return 0;
    size_t new_cap = builder->cap ? builder->cap : 256;
    while (builder->size + more > new_cap) {
        if (new_cap > (SIZE_MAX / 2)) return -1;
        new_cap *= 2;
    }
    if (new_cap > PARCEL_MAX_ALLOC) return -1;
    uint8_t* new_buffer = (uint8_t*)malloc(new_cap);
    if (!new_buffer) return -1;
    if (builder->buf && builder->size) {
        memcpy(new_buffer, builder->buf, builder->size);
        memset(builder->buf, 0, builder->cap);
        free(builder->buf);
    }
    builder->buf = new_buffer;
    builder->cap = new_cap;
    return 0;
}

void parcel_writeInt32(ParcelBuilder* builder, int32_t value) {
    if (parcel_ensure(builder, 4) == 0) {
        memcpy(builder->buf + builder->size, &value, 4);
        builder->size += 4;
    }
}

void parcel_writeInt64(ParcelBuilder* builder, int64_t value) {
    if (parcel_ensure(builder, 8) == 0) {
        memcpy(builder->buf + builder->size, &value, 8);
        builder->size += 8;
    }
}

static void parcel_align(ParcelBuilder* builder) {
    size_t pad = (4U - (builder->size & 3U)) & 3U;
    if (pad) {
        if (parcel_ensure(builder, pad) == 0) {
            memset(builder->buf + builder->size, 0, pad);
            builder->size += pad;
        }
    }
}

void parcel_writeString16(ParcelBuilder* builder, const char* string) {
    if (!string) {
        parcel_writeInt32(builder, -1);
        return;
    }
    int32_t length = 0;
    while (string[length] != '\0') ++length;
    if (length > 0x7FFFFFFF) length = 0x7FFFFFFF;
    parcel_writeInt32(builder, length);
    size_t need = 2 * (size_t)(length + 1) + 4;
    if (need < (size_t)length) return;
    if (parcel_ensure(builder, need) == 0) {
        for (int i = 0; i < length; ++i) {
            uint16_t char_code = (uint16_t)(uint8_t)string[i];
            memcpy(builder->buf + builder->size, &char_code, 2);
            builder->size += 2;
        }
        uint16_t zero = 0;
        memcpy(builder->buf + builder->size, &zero, 2);
        builder->size += 2;
        parcel_align(builder);
    }
}

void parcel_writeInterfaceToken(ParcelBuilder* builder, const char* interface_name) {
    int api_level = android_get_device_api_level();
    const uint32_t STRICT_MODE_PENALTY_GATHER = (api_level >= 29) ? 0x80000000u : 0x00400000u;
    parcel_writeInt32(builder, (int32_t)STRICT_MODE_PENALTY_GATHER);
    if (api_level >= 30) {
        parcel_writeInt32(builder, -1);
        parcel_writeInt32(builder, 0x53595354);
    } else if (api_level == 29) {
        parcel_writeInt32(builder, -1);
    }
    parcel_writeString16(builder, interface_name);
}

void parcel_writeString8(ParcelBuilder* builder, const char* string) {
    if (!string) {
        parcel_writeInt32(builder, -1);
        return;
    }
    int32_t length = 0;
    while (string[length] != '\0') ++length;
    if (length > 0x7FFFFFFF) length = 0x7FFFFFFF;
    parcel_writeInt32(builder, length);
    if (parcel_ensure(builder, (size_t)(length + 1) + 3) == 0) {
        memcpy(builder->buf + builder->size, string, (size_t)length);
        builder->size += (size_t)length;
        builder->buf[builder->size++] = 0;
        parcel_align(builder);
    }
}

void parcel_writeVersionedPackage(ParcelBuilder* builder, const char* packageName, int64_t versionCode) {
    parcel_writeString8(builder, packageName);
    parcel_writeInt64(builder, versionCode);
}