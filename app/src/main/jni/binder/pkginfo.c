#include "pkginfo.h"
#include "binder.h"
#include "parcel.h"
#include "my_syscall.h"
#include <android/api-level.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include <fcntl.h>

#define GET_SIGNATURES 0x0000000000000040ULL
#define GET_SIGNING_CERTIFICATES 0x0000000008000000ULL
#define MAX_SIGNATURE_LEN (1 << 20)

static int parse_der_length(const uint8_t* data, size_t length, size_t* out_total_size, size_t* out_header_size) {
    if (!data || !out_total_size || !out_header_size || length < 2) return 0;
    size_t total_size, header_size;
    if (data[1] < 0x80) {
        header_size = 2;
        total_size = 2 + (size_t)data[1];
    } else if (data[1] == 0x81 && length >= 3) {
        header_size = 3;
        total_size = 3 + (size_t)data[2];
    } else if (data[1] == 0x82 && length >= 4) {
        size_t content = ((size_t)data[2] << 8) | (size_t)data[3];
        header_size = 4;
        total_size = 4 + content;
    } else {
        return 0;
    }
    if (total_size > length) return 0;
    *out_total_size = total_size;
    *out_header_size = header_size;
    return 1;
}

static int parse_der_certificate(const uint8_t* data, size_t length) {
    if (length < 32 || data[0] != 0x30) return 0;
    size_t outer_total, outer_header;
    if (!parse_der_length(data, length, &outer_total, &outer_header)) return 0;
    if (outer_total != length) return 0;
    const uint8_t* inner_data = data + outer_header;
    size_t inner_length = length - outer_header;
    if (inner_length < 4 || inner_data[0] != 0x30) return 0;
    size_t tbs_total, tbs_header;
    if (!parse_der_length(inner_data, inner_length, &tbs_total, &tbs_header)) return 0;
    if (tbs_total > inner_length) return 0;
    int has_bit_string = 0;
    size_t scan_start = (length > 600) ? length - 600 : 0;
    for (size_t i = length - 2; i > scan_start; i--) {
        if (data[i] != 0x03) continue;
        size_t bitstring_total = 0, bitstring_header = 0;
        if (parse_der_length(data + i, length - i, &bitstring_total, &bitstring_header)) {
            if (i + bitstring_total == length && bitstring_total >= 4) {
                has_bit_string = 1;
                break;
            }
        }
    }
    if (!has_bit_string) return 0;
    static const uint8_t oid_rsa[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01};
    static const uint8_t oid_ec[]  = {0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    for (size_t k = 0; k + sizeof(oid_rsa) <= length; ++k) {
        if (data[k] != 0x06) continue;
        if (memcmp(data + k, oid_rsa, sizeof(oid_rsa)) == 0) return 1;
        if (memcmp(data + k, oid_ec, sizeof(oid_ec)) == 0) return 1;
    }
    return 0;
}

static int find_cert_structured(const uint8_t* data, size_t size, const uint8_t** certificate, size_t* length) {
    for (size_t i = 0; i + 12 < size; i += 4) {
        int32_t array_length;
        memcpy(&array_length, data + i, 4);
        if (array_length < 1 || array_length > 16) continue;
        int32_t presence;
        memcpy(&presence, data + i + 4, 4);
        if (presence != 1) continue;
        int32_t cert_length;
        memcpy(&cert_length, data + i + 8, 4);
        if (cert_length < 128 || cert_length > MAX_SIGNATURE_LEN) continue;
        if (i + 12 + (size_t)cert_length > size) continue;
        const uint8_t* position = data + i + 12;
        if (parse_der_certificate(position, (size_t)cert_length)) {
            *certificate = position;
            *length = (size_t)cert_length;
            return 1;
        }
    }
    return 0;
}

static int find_cert(const uint8_t* data, size_t size, const uint8_t** certificate, size_t* length) {
    if (size < 16) return 0;
    return find_cert_structured(data, size, certificate, length);
}

static int is_package_name(const char* string) {
    int has_dot = 0;
    if (!string || !string[0]) return 0;
    for (size_t i = 0; string[i]; ++i) {
        char c = string[i];
        if (c == '.') {
            has_dot = 1;
            continue;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_') {
            continue;
        }
        return 0;
    }
    return has_dot;
}

static int copy_string(char* destination, size_t destination_size, const char* source) {
    if (!destination || destination_size == 0 || !source || !source[0]) return -1;
    size_t i = 0;
    while (source[i] && i + 1 < destination_size) {
        destination[i] = source[i];
        i++;
    }
    destination[i] = '\0';
    return 0;
}

static const char* find_base_apk(const char* line) {
    static const char base_apk[] = "/base.apk";
    const char* result = NULL;
    for (size_t i = 0; line[i]; ++i) {
        size_t j = 0;
        while (base_apk[j] && line[i + j] == base_apk[j]) j++;
        if (!base_apk[j]) {
            result = line + i;
        }
    }
    return result;
}

static int read_apk_path(const char* line, const char* base_apk, char* path, size_t path_size) {
    if (!line || !base_apk || !path || path_size == 0) return -1;
    const char* start = base_apk;
    while (start > line && start[-1] != ' ' && start[-1] != '\t') start--;
    const char* end = base_apk + sizeof("/base.apk") - 1;
    if (*start != '/' || end <= start) return -1;
    size_t length = 0;
    for (const char* p = start; p < end && length + 1 < path_size; ++p) {
        path[length++] = *p;
    }
    path[length] = '\0';
    return length > 0 ? 0 : -1;
}

static int read_package_name_from_apk_path(const char* apk_path, char* package_name, size_t package_size) {
    if (!apk_path || !package_name || package_size == 0) return -1;
    const char* base_apk = find_base_apk(apk_path);
    if (!base_apk) return -1;
    const char* start = base_apk;
    while (start > apk_path && start[-1] != '/') start--;
    if (start >= base_apk) return -1;
    size_t length = 0;
    for (const char* p = start; p < base_apk && length + 1 < package_size; ++p) {
        if (*p == '-') break;
        package_name[length++] = *p;
    }
    package_name[length] = '\0';
    return is_package_name(package_name) ? 0 : -1;
}

static int get_package_name(const char* self_package, char* buffer, size_t size) {
    if (size == 0) return -1;
    buffer[0] = '\0';
    int fd = (int)syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    if (fd < 0) return -1;
    char read_buffer[4096];
    char line[2048];
    size_t line_length = 0;
    int result = -1;
    char self_name[256];
    self_name[0] = '\0';
    for (;;) {
        long n = syscall_invoke(__NR_read, fd, (long)read_buffer, sizeof(read_buffer), 0, 0, 0);
        if (n <= 0) {
            if (line_length == 0) break;
            read_buffer[0] = '\n';
            n = 1;
        }
        for (long i = 0; i < n; ++i) {
            char c = read_buffer[i];
            if (c == '\n') {
                line[line_length] = '\0';
                const char* base_apk = find_base_apk(line);
                if (base_apk) {
                    char apk_path[1024];
                    char candidate[256];
                    if (read_apk_path(line, base_apk, apk_path, sizeof(apk_path)) == 0 &&
                        read_package_name_from_apk_path(apk_path, candidate, sizeof(candidate)) == 0) {
                        if (strcmp(candidate, self_package) != 0) {
                            copy_string(buffer, size, candidate);
                            result = 0;
                            goto done;
                        }
                        if (!self_name[0]) {
                            copy_string(self_name, sizeof(self_name), candidate);
                        }
                    }
                }
                line_length = 0;
                continue;
            }
            if (line_length + 1 < sizeof(line)) {
                line[line_length++] = c;
            }
        }
    }
    if (self_name[0]) {
        copy_string(buffer, size, self_name);
        result = 0;
    }
done:
    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
    return result;
}

static unsigned char* try_get_certificate(int fd, uint32_t handle, const void* data, size_t size, uint32_t code, size_t* length) {
    const void* reply_buffer = NULL;
    size_t reply_size = 0;
    const void* reply_offsets = NULL;
    size_t reply_offsets_size = 0;
    if (binder_transact(fd, handle, code, data, size, &reply_buffer, &reply_size, &reply_offsets, &reply_offsets_size) != 0) {
        return NULL;
    }
    const uint8_t* certificate = NULL;
    size_t certificate_length = 0;
    unsigned char* result = NULL;
    if (find_cert(reply_buffer, reply_size, &certificate, &certificate_length)) {
        result = calloc(1, certificate_length);
        if (result) {
            memcpy(result, certificate, certificate_length);
            *length = certificate_length;
        }
    }
    free_binder_buffer(fd, reply_buffer);
    return result;
}

static unsigned char* get_signature(int fd, uint32_t handle, const char* package_name, size_t* length) {
    int api_level = android_get_device_api_level();
    uint32_t flags = (api_level >= 28) ? GET_SIGNING_CERTIFICATES : GET_SIGNATURES;
    uint32_t code = (api_level < 23) ? 2 : 3;
    ParcelBuilder builder;
    parcel_init(&builder);
    parcel_writeInterfaceToken(&builder, "android.content.pm.IPackageManager");
    parcel_writeString16(&builder, package_name);
    if (api_level >= 33) {
        parcel_writeInt64(&builder, (int64_t)flags);
    } else {
        parcel_writeInt32(&builder, (int32_t)flags);
    }
    parcel_writeInt32(&builder, getuid() / 100000U);
    unsigned char* result = try_get_certificate(fd, handle, builder.buf, builder.size, code, length);
    parcel_free(&builder);
    if (result) {
        return result;
    }
    if (api_level >= 33) {
        ParcelBuilder builder2;
        parcel_init(&builder2);
        parcel_writeInterfaceToken(&builder2, "android.content.pm.IPackageManager");
        parcel_writeVersionedPackage(&builder2, package_name, -1LL);
        parcel_writeInt64(&builder2, (int64_t)flags);
        parcel_writeInt32(&builder2, getuid() / 100000U);
        result = try_get_certificate(fd, handle, builder2.buf, builder2.size, 4, length);
        parcel_free(&builder2);
    }
    return result;
}

unsigned char* get_signature_from_binder(const char* self_package, size_t* length) {
    if (!length) {
        return NULL;
    }
    *length = 0;
    char package_name[256];
    if (get_package_name(self_package, package_name, sizeof(package_name)) != 0) {
        return NULL;
    }
    BinderDriver driver;
    if (open_binder_driver(&driver) != 0) {
        return NULL;
    }
    unsigned char* result = NULL;
    uint32_t handle = 0;
    if (get_binder_service_handle(driver.fd, "package", &handle) != 0) {
        goto cleanup;
    }
    result = get_signature(driver.fd, handle, package_name, length);
cleanup:
    close_binder_driver(&driver);
    return result;
}