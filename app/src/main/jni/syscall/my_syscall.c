#include "my_syscall.h"
#include <sys/mman.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

typedef long (*syscall_function)(long, long, long, long, long, long, long);
static volatile uint32_t* volatile xor_key = NULL;
static volatile syscall_function* volatile syscall_trampoline = NULL;

static uint32_t shellcode_template[] = {
    0xAA0003E8,
    0xAA0103E0,
    0xAA0203E1,
    0xAA0303E2,
    0xAA0403E3,
    0xAA0503E4,
    0xAA0603E5,
    0xD4000001,
    0xD65F03C0,
};
#define CODE_WORDS (sizeof(shellcode_template) / sizeof(shellcode_template[0]))

static void __attribute__((constructor)) init_syscall_trampoline(void) {
    size_t code_size = sizeof(shellcode_template);
    void* mem = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return;
    memcpy(mem, shellcode_template, code_size);
    __clear_cache(mem, (char*)mem + code_size);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint32_t key = (uint32_t)(ts.tv_nsec ^ ts.tv_sec ^ (uintptr_t)mem ^ 0x9E3779B9);
    uint32_t* code = (uint32_t*)mem;
    for (size_t i = 0; i < CODE_WORDS; i++) code[i] ^= key;
    __clear_cache(mem, (char*)mem + code_size);
    memset((void*)shellcode_template, 0, sizeof(shellcode_template));
    xor_key = (uint32_t*)malloc(sizeof(uint32_t));
    if (!xor_key) { munmap(mem, code_size); return; }
    *xor_key = key;
    syscall_trampoline = (syscall_function*)malloc(sizeof(syscall_function));
    if (!syscall_trampoline) { munmap(mem, code_size); free((void*)xor_key); xor_key = NULL; return; }
    *syscall_trampoline = (syscall_function)mem;
}

long syscall_invoke(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    if (!syscall_trampoline || !*syscall_trampoline || !xor_key) return -1;
    syscall_function function = *syscall_trampoline;
    uint32_t key = *xor_key;
    uint32_t* code = (uint32_t*)function;
    for (size_t i = 0; i < CODE_WORDS; i++) code[i] ^= key;
    __clear_cache(code, code + CODE_WORDS);
    long ret = function(number, arg1, arg2, arg3, arg4, arg5, arg6);
    for (size_t i = 0; i < CODE_WORDS; i++) code[i] ^= key;
    __clear_cache(code, code + CODE_WORDS);
    return ret;
}