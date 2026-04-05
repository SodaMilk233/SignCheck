#include "binder.h"
#include "parcel.h"
#include "my_syscall.h"
#include <unistd.h>
#include <linux/android/binder.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static int parse_binder_device_path(const char* path) {
    if (!path) return 0;
    return strcmp(path, "/dev/binder") == 0 ||
           strcmp(path, "/dev/binderfs/binder") == 0;
}

static int find_binder_fd(void) {
    int dir_fd = (int)syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/fd", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (dir_fd < 0) return -1;
    char buffer[4096];
    int result = -1;
    for (;;) {
        long bytes_read = (long)syscall_invoke(__NR_getdents64, dir_fd, (long)buffer, sizeof(buffer), 0, 0, 0);
        if (bytes_read <= 0) break;
        for (long buffer_offset = 0; buffer_offset <= bytes_read - (long)sizeof(struct linux_dirent64); ) {
            struct linux_dirent64* dirent = (struct linux_dirent64*)(buffer + buffer_offset);
            if (dirent->d_reclen == 0 || buffer_offset + dirent->d_reclen > bytes_read) break;
            buffer_offset += dirent->d_reclen;
            int file_descriptor = 0;
            for (int i = 0; ; ++i) {
                if (i == 0 && dirent->d_name[i] == '\0') {
                    file_descriptor = -1;
                    break;
                }
                if (dirent->d_name[i] == '\0') {
                    break;
                }
                if (dirent->d_name[i] < '0' || dirent->d_name[i] > '9') {
                    file_descriptor = -1;
                    break;
                }
                file_descriptor = file_descriptor * 10 + (dirent->d_name[i] - '0');
            }
            if (file_descriptor < 0) continue;
            char link[256];
            long length = (long)syscall_invoke(__NR_readlinkat, dir_fd, (long)dirent->d_name, (long)link, sizeof(link) - 1, 0, 0);
            if (length <= 0 || (size_t)length >= sizeof(link)) continue;
            link[length] = '\0';
            if (!parse_binder_device_path(link)) continue;
            struct binder_version version;
            memset(&version, 0, sizeof(version));
            if (syscall_invoke(__NR_ioctl, file_descriptor, BINDER_VERSION, (long)&version, 0, 0, 0) >= 0) {
                result = file_descriptor;
                goto done;
            }
        }
    }
done:
    syscall_invoke(__NR_close, dir_fd, 0, 0, 0, 0, 0);
    return result;
}

static void init_binder_driver(BinderDriver* driver) {
    if (!driver) return;
    driver->fd = -1;
}

int open_binder_driver(BinderDriver* driver) {
    if (!driver) return -1;
    init_binder_driver(driver);
    int fd = find_binder_fd();
    if (fd >= 0) {
        driver->fd = fd;
        return 0;
    }
    return -1;
}

void close_binder_driver(BinderDriver* driver) {
    if (!driver) return;
    driver->fd = -1;
}

static int binder_write_read_transaction(int fd, uint32_t handle, uint32_t code, const void* payload, size_t payload_size, const void** out_buffer, size_t* out_size, const void** out_offsets, size_t* out_offsets_size) {
    struct { uint32_t cmd; struct binder_transaction_data tr; } __attribute__((packed)) write_cmd;
    memset(&write_cmd, 0, sizeof(write_cmd));
    write_cmd.cmd = BC_TRANSACTION;
    write_cmd.tr.target.handle = handle;
    write_cmd.tr.code = code;
    write_cmd.tr.flags = TF_ACCEPT_FDS;
    write_cmd.tr.data_size = payload_size;
    write_cmd.tr.offsets_size = 0;
    write_cmd.tr.data.ptr.buffer = (binder_uintptr_t)payload;
    uint8_t read_buffer[32768];
    struct binder_write_read write_read;
    memset(&write_read, 0, sizeof(write_read));
    write_read.write_size = sizeof(write_cmd);
    write_read.write_buffer = (binder_uintptr_t)&write_cmd;
    write_read.read_size = sizeof(read_buffer);
    write_read.read_buffer = (binder_uintptr_t)read_buffer;
    for (int iteration = 0; iteration < 50; iteration++) {
        long ret;
        do {
            ret = syscall_invoke(__NR_ioctl, fd, BINDER_WRITE_READ, (long)&write_read, 0, 0, 0);
        } while (ret == -EINTR);
        if (ret < 0) return -1;
        size_t offset = 0;
        while (offset + sizeof(uint32_t) <= write_read.read_consumed) {
            uint32_t command;
            memcpy(&command, read_buffer + offset, sizeof(command));
            offset += sizeof(command);
            switch (command) {
                case BR_NOOP:
                case BR_SPAWN_LOOPER:
                case BR_OK:
                case BR_TRANSACTION_PENDING_FROZEN:
                case BR_TRANSACTION_COMPLETE:
                    break;
                case BR_REPLY: {
                    if (offset + sizeof(struct binder_transaction_data) > write_read.read_consumed) return -1;
                    struct binder_transaction_data transaction;
                    memcpy(&transaction, read_buffer + offset, sizeof(transaction));
                    *out_buffer = (const void*)(uintptr_t)transaction.data.ptr.buffer;
                    *out_size = transaction.data_size;
                    *out_offsets = (const void*)(uintptr_t)transaction.data.ptr.offsets;
                    *out_offsets_size = transaction.offsets_size;
                    return 0;
                }
                case BR_FAILED_REPLY:
                case BR_DEAD_REPLY:
                case BR_FROZEN_REPLY:
                    return -1;
                case BR_TRANSACTION:
                    offset += sizeof(struct binder_transaction_data);
                    break;
                case BR_ACQUIRE:
                case BR_RELEASE:
                case BR_INCREFS:
                case BR_DECREFS:
                    offset += 2 * sizeof(binder_uintptr_t);
                    break;
                default:
                    return -1;
            }
        }
        write_read.write_size = 0;
        write_read.read_size = sizeof(read_buffer);
        write_read.read_consumed = 0;
    }
    return -1;
}

int free_binder_buffer(int fd, const void* buffer) {
    struct { uint32_t cmd; binder_uintptr_t ptr; } __attribute__((packed)) write_cmd;
    write_cmd.cmd = BC_FREE_BUFFER;
    write_cmd.ptr = (binder_uintptr_t)buffer;
    struct binder_write_read write_read;
    memset(&write_read, 0, sizeof(write_read));
    write_read.write_size = sizeof(write_cmd);
    write_read.write_buffer = (binder_uintptr_t)&write_cmd;
    return syscall_invoke(__NR_ioctl, fd, BINDER_WRITE_READ, (long)&write_read, 0, 0, 0) < 0 ? -1 : 0;
}

int get_binder_service_handle(int fd, const char* name, uint32_t* handle) {
    ParcelBuilder builder;
    parcel_init(&builder);
    parcel_writeInterfaceToken(&builder, "android.os.IServiceManager");
    parcel_writeString16(&builder, name);
    const void* reply_buffer = NULL;
    size_t reply_size = 0;
    const void* reply_offsets = NULL;
    size_t reply_offsets_size = 0;
    int result = binder_write_read_transaction(fd, 0, 2, builder.buf, builder.size, &reply_buffer, &reply_size, &reply_offsets, &reply_offsets_size);
    if (result != 0) {
        result = binder_write_read_transaction(fd, 0, 1, builder.buf, builder.size, &reply_buffer, &reply_size, &reply_offsets, &reply_offsets_size);
    }
    parcel_free(&builder);
    if (result != 0) return -1;
    if (reply_offsets_size >= sizeof(binder_size_t)) {
        binder_size_t first_offset;
        memcpy(&first_offset, reply_offsets, sizeof(first_offset));
        if ((size_t)first_offset + sizeof(struct flat_binder_object) <= reply_size) {
            const struct flat_binder_object* flat_object = (const struct flat_binder_object*)((const uint8_t*)reply_buffer + first_offset);
            if (flat_object->hdr.type == BINDER_TYPE_HANDLE || flat_object->hdr.type == BINDER_TYPE_WEAK_HANDLE) {
                *handle = flat_object->handle;
                free_binder_buffer(fd, reply_buffer);
                return 0;
            }
        }
    }
    free_binder_buffer(fd, reply_buffer);
    return -1;
}

int binder_transact(int fd, uint32_t handle, uint32_t code, const void* payload, size_t payload_size, const void** reply_data, size_t* reply_size, const void** reply_offsets, size_t* reply_offsets_size) {
    return binder_write_read_transaction(fd, handle, code, payload, payload_size, reply_data, reply_size, reply_offsets, reply_offsets_size);
}
