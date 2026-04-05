cmake_minimum_required(VERSION 3.22.1)
project(SignVerify)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -fvisibility=hidden -Wall -Wextra -fomit-frame-pointer -fdata-sections -ffunction-sections -fno-asynchronous-unwind-tables -fno-unwind-tables")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--strip-all -Wl,-z,now -Wl,-z,relro -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/hide_map.txt -Wl,--pack-dyn-relocs=none")

find_library(log-lib log)

add_library(SignVerify SHARED
    main.c
    binder/binder.c
    binder/parcel.c
    binder/pkginfo.c
    crypto/sha256.c
    syscall/my_syscall.c
)

target_include_directories(SignVerify PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/binder
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/syscall
)

target_link_libraries(SignVerify ${log-lib})
