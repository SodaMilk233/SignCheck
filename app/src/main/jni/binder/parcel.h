#ifndef PARCEL_H
#define PARCEL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t* buf;
    size_t size;
    size_t cap;
} ParcelBuilder;

void parcel_init(ParcelBuilder* builder);
void parcel_free(ParcelBuilder* builder);
void parcel_writeInt32(ParcelBuilder* builder, int32_t value);
void parcel_writeInt64(ParcelBuilder* builder, int64_t value);
void parcel_writeString16(ParcelBuilder* builder, const char* string);
void parcel_writeString8(ParcelBuilder* builder, const char* string);
void parcel_writeInterfaceToken(ParcelBuilder* builder, const char* interface_name);
void parcel_writeVersionedPackage(ParcelBuilder* builder, const char* packageName, int64_t versionCode);

#endif