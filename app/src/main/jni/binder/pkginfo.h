#ifndef PKGINFO_H
#define PKGINFO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned char* get_signature_from_binder(const char* package_name, size_t* length);

#ifdef __cplusplus
}
#endif

#endif