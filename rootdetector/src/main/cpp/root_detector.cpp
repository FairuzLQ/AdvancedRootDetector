#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <dlfcn.h>
#include <signal.h>
#include <setjmp.h>
#include <link.h>      // dl_iterate_phdr
#include <pthread.h>

#define TAG "RDNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// =============================================================================
// Helpers
// =============================================================================

static bool file_exists_libc(const char* path) {
    struct stat st{};
    return stat(path, &st) == 0;
}

// Portable stat via direct syscall — bypasses libc hooks on the fstatat family.
// __NR_newfstatat (arm64/x86_64=262, arm64=79) vs __NR_fstatat64 (arm32=327, x86=300)
static bool file_exists_syscall(const char* path) {
    struct stat st{};
#if defined(__NR_newfstatat)
    return syscall(__NR_newfstatat, AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) == 0;
#elif defined(__NR_fstatat64)
    return syscall(__NR_fstatat64, AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) == 0;
#else
    return stat(path, &st) == 0;
#endif
}

static std::string read_file(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string str_lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

static bool str_contains_lower(const std::string& hay, const char* needle) {
    return str_lower(hay).find(needle) != std::string::npos;
}

// =============================================================================
// 1. ENHANCED /proc/self/maps analysis
//
//    Improvements over v1:
//    - Filter out paths under /system/, /apex/, /vendor/ (signed system libs)
//    - Filter out this app's own APK path
//    - Only flag anonymous paths (injected code not from any file)
// =============================================================================

static const char* SYSTEM_PREFIXES[] = {
    "/system/", "/apex/", "/vendor/", "/product/", "/odm/",
    "/data/dalvik-cache/", "/data/app/", nullptr
};

static bool is_system_path(const std::string& path) {
    for (int i = 0; SYSTEM_PREFIXES[i]; i++) {
        if (path.find(SYSTEM_PREFIXES[i]) == 0) return true;
    }
    return false;
}

static const char* SUSPICIOUS_PATTERNS[] = {
    "magisk", "zygisk", "shamiko", "lspd", "lspatch",
    "xposed", "riru", "frida", "objection", "ksu", "apatch",
    "rezygisk", "zygnext", "dreamland", "pine_bridge",
    nullptr
};

static std::vector<std::string> scan_maps_suspicious_libs() {
    std::vector<std::string> hits;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return hits;

    std::string line;
    while (std::getline(maps, line)) {
        // Extract the pathname (last column, if present)
        size_t pos = 0;
        for (int fields = 0; fields < 5 && pos < line.size(); fields++) {
            while (pos < line.size() && line[pos] == ' ') pos++;
            while (pos < line.size() && line[pos] != ' ') pos++;
        }
        while (pos < line.size() && line[pos] == ' ') pos++;
        std::string path = (pos < line.size()) ? line.substr(pos) : "";

        // Skip system/framework paths — they are signed and legitimate
        if (!path.empty() && is_system_path(path)) continue;
        // Skip well-known anonymous segments
        if (path == "[stack]" || path == "[heap]" || path == "[vvar]" ||
            path == "[vdso]" || path == "[vsyscall]") continue;

        std::string lower = str_lower(line);
        for (int i = 0; SUSPICIOUS_PATTERNS[i]; i++) {
            if (lower.find(SUSPICIOUS_PATTERNS[i]) != std::string::npos) {
                hits.push_back(line);
                break;
            }
        }
    }
    return hits;
}

// =============================================================================
// 2. Anonymous RWX mapping detection
//
//    Injected shellcode/patches appear as anonymous executable pages.
//    Legitimate JIT pages are named (dalvik-jit-code-cache, etc.) on modern
//    Android. Truly anonymous rwx pages > 16KB are a strong code-injection signal.
// =============================================================================

static std::vector<std::string> find_anonymous_rwx_mappings() {
    std::vector<std::string> hits;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return hits;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.size() < 18) continue;

        // Permissions are at offset 18: e.g. "rwxp"
        const std::string& perms = line.substr(18, 4);
        if (perms != "rwxp" && perms != "rwxs") continue;

        // Check if anonymous (no file path, device=00:00)
        if (line.find("00:00") == std::string::npos) continue;

        // Inode should be 0 for anonymous
        // Extract pathname (after 5 fields)
        size_t pos = 0;
        for (int f = 0; f < 5 && pos < line.size(); f++) {
            while (pos < line.size() && line[pos] == ' ') pos++;
            while (pos < line.size() && line[pos] != ' ') pos++;
        }
        while (pos < line.size() && line[pos] == ' ') pos++;
        std::string path = (pos < line.size()) ? line.substr(pos) : "";

        // Skip named ashmem (ART JIT uses named ashmem)
        if (!path.empty()) continue;

        // Compute mapping size
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;
        unsigned long long start = strtoull(line.c_str(), nullptr, 16);
        unsigned long long end   = strtoull(line.c_str() + dash + 1, nullptr, 16);
        unsigned long long size  = end - start;

        // Only flag significant-size anonymous rwx regions (> 16KB)
        if (size > 16384) {
            char buf[128];
            snprintf(buf, sizeof(buf), "anon rwx %llx-%llx size=%llukB", start, end, size/1024);
            hits.push_back(buf);
        }
    }
    return hits;
}

// =============================================================================
// 3. KernelSU syscall probe — safe version with SIGSYS handler
// =============================================================================

static sigjmp_buf g_ksu_jmp;
static volatile sig_atomic_t g_sigsys_caught = 0;

static void sigsys_handler(int, siginfo_t*, void*) {
    g_sigsys_caught = 1;
    siglongjmp(g_ksu_jmp, 1);
}

static bool probe_kernelsu_syscall_safe() {
#if defined(__aarch64__) || defined(__arm__)
    struct sigaction new_sa{}, old_sa{};
    new_sa.sa_sigaction = sigsys_handler;
    new_sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&new_sa.sa_mask);
    if (sigaction(SIGSYS, &new_sa, &old_sa) != 0) return false;

    g_sigsys_caught = 0;
    bool detected = false;
    if (sigsetjmp(g_ksu_jmp, 1) == 0) {
        long ret = syscall(0xDEADBEEF, 2 /*KSU_CMD_GET_VERSION*/, nullptr, nullptr, nullptr);
        if (ret != -1 || errno != ENOSYS) detected = true;
    }
    sigaction(SIGSYS, &old_sa, nullptr);
    return detected && (g_sigsys_caught == 0);
#else
    return false;
#endif
}

// =============================================================================
// 4. APatch probe
// =============================================================================

static bool probe_apatch() {
    return file_exists_syscall("/dev/kp") || file_exists_syscall("/dev/apatch");
}

// =============================================================================
// 5. dlopen — check already-loaded root libraries
// =============================================================================

static std::vector<std::string> probe_loaded_libs() {
    std::vector<std::string> found;
    const char* libs[] = {
        "libzygisk.so", "liblspd.so", "libriru.so",
        "libedxp.so", "libshamiko.so", nullptr
    };
    for (int i = 0; libs[i]; i++) {
        void* h = dlopen(libs[i], RTLD_NOLOAD);
        if (h) { found.push_back(libs[i]); dlclose(h); }
    }
    return found;
}

// =============================================================================
// 6. Symbol probe
//    dlsym(RTLD_DEFAULT, sym) searches ALL loaded libraries in link order.
//    If these symbols exist, the corresponding framework is injected.
// =============================================================================

static std::vector<std::string> probe_root_symbols() {
    std::vector<std::string> found;
    struct { const char* sym; const char* tag; } probes[] = {
        // Xposed / LSPosed
        { "xposedInit",                    "Classic Xposed module init"        },
        { "lspd_context",                  "LSPosed context"                   },
        // Zygisk
        { "zygisk_module_entry",           "Zygisk module entry"               },
        // Riru
        { "riru_api_version",              "Riru framework API version"        },
        { "riru_api_version_backup",       "Riru backup symbol"                },
        // KSU
        { "ksu_hook_func",                 "KernelSU hook function"            },
        // Pine / Dreamland
        { "pine_bridge_init",              "Pine bridge init"                  },
        { "dreamland_init",                "Dreamland init"                    },
        // Frida — present in ANY Frida gadget/agent regardless of filename or rename
        { "frida_agent_main",              "Frida agent main entry"            },
        { "gum_init_embedded",             "Frida Gum embedded init"           },
        { "gum_process_enumerate_modules", "Frida Gum module enumerator"       },
        { "frida_deinit",                  "Frida runtime deinit"              },
        { "gum_interceptor_obtain",        "Frida Gum interceptor"             },
        { "gum_memory_scan",               "Frida Gum memory scan"             },
        { nullptr, nullptr }
    };
    for (int i = 0; probes[i].sym; i++) {
        if (dlsym(RTLD_DEFAULT, probes[i].sym) != nullptr) {
            found.push_back(std::string(probes[i].sym) + " [" + probes[i].tag + "]");
        }
    }
    return found;
}

// =============================================================================
// 6b. Frida port probe — /proc/net/tcp[6] for port 27042 (0x69A2)
//
//     Port 27042 is Frida's well-known default. It won't appear for a renamed
//     gadget (which is in-process), but catches standalone frida-server even
//     if the binary is renamed, since the port remains the same unless explicitly
//     changed. Reported as FRIDA_PORT to distinguish from in-process detection.
// =============================================================================

static bool probe_frida_port() {
    // 27042 in big-endian hex = 0x69A2
    const char* tcp_files[] = { "/proc/net/tcp", "/proc/net/tcp6", nullptr };
    for (int f = 0; tcp_files[f]; f++) {
        std::ifstream tcp(tcp_files[f]);
        if (!tcp.is_open()) continue;
        std::string line;
        while (std::getline(tcp, line)) {
            // local_address field: "IP:PORT" — port is last 4 hex chars before space
            // e.g. "00000000:69A2 ..."
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            // Port is the 4 chars after the colon
            std::string port_hex = line.substr(colon + 1, 4);
            // Normalise to upper
            for (auto& c : port_hex) c = (char)toupper((unsigned char)c);
            if (port_hex == "69A2") return true;
        }
    }
    return false;
}

// =============================================================================
// 7. Capability elevation check
//
//    A normal Android app has CapEff = 0000000000000000 in /proc/self/status.
//    ANY non-zero CapEff means the process was granted elevated Linux capabilities
//    (e.g., CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH) by a root mechanism.
//
//    False positive risk: ZERO for user-installed APKs.
//    System apps MAY have non-zero CapEff, but we're a third-party app.
// =============================================================================

static std::string get_cap_eff() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return "";
    std::string line;
    while (std::getline(status, line)) {
        if (line.substr(0, 7) == "CapEff:") {
            std::string val = line.substr(7);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t\r\n") + 1);
            return val;
        }
    }
    return "";
}

static bool has_elevated_capabilities(std::string& cap_out) {
    cap_out = get_cap_eff();
    if (cap_out.empty()) return false;
    for (char c : cap_out) {
        if (c != '0') return true;
    }
    return false;
}

// =============================================================================
// 8. UID consistency check — getuid() libc vs raw syscall
//
//    Root hiding tools (Magisk HideMyRoot, some KSU configs) can hook libc's
//    getuid() to return the original UID while the process actually runs as root.
//    Direct syscall bypasses the hook.
// =============================================================================

static bool check_uid_consistency(long& uid_syscall_out, uid_t& uid_libc_out) {
    uid_libc_out   = getuid();
    uid_syscall_out = syscall(__NR_getuid);
    return (long)uid_libc_out != uid_syscall_out;
}

static bool is_root_uid() {
    return syscall(__NR_getuid) == 0;
}

// =============================================================================
// 9. File hiding detection — libc open() vs direct SYS_openat
//
//    Root hiding tools (MagiskHide, Shamiko, KSU SuHide) hook open/stat in libc
//    to make root paths return ENOENT for processes on the DenyList/hide list.
//    Raw kernel syscalls bypass these userspace hooks.
//
//    Detection logic:
//      libc says ENOENT (not found)
//      AND syscall says EACCES (exists but no permission) or opens successfully
//      → the file IS being hidden from our process via libc hooking
// =============================================================================

struct FileHideResult {
    bool hiding_detected;
    const char* path;
    int libc_errno;
    int syscall_errno;
};

static FileHideResult check_single_path_hiding(const char* path) {
    // Test via libc
    int libc_fd = open(path, O_RDONLY | O_CLOEXEC);
    int libc_err = errno;
    if (libc_fd >= 0) { close(libc_fd); libc_err = 0; }

    // Test via direct syscall (bypasses libc PLT hooks)
    int raw_fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    int raw_err = errno;
    if (raw_fd >= 0) { close(raw_fd); raw_err = 0; }

    // Hiding: libc says "doesn't exist" but kernel says "exists, no permission" or "success"
    bool libc_not_found   = (libc_fd < 0 && libc_err == ENOENT);
    bool syscall_found     = (raw_fd >= 0) || (raw_fd < 0 && raw_err == EACCES);

    return { libc_not_found && syscall_found, path, libc_err, raw_err };
}

static std::vector<std::string> detect_file_hiding() {
    const char* root_paths[] = {
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/ksu",
        "/data/adb/ksunext",
        "/data/adb/ap",
        "/data/adb/modules",
        nullptr
    };
    std::vector<std::string> hits;
    for (int i = 0; root_paths[i]; i++) {
        auto res = check_single_path_hiding(root_paths[i]);
        if (res.hiding_detected) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s [libc=ENOENT, syscall=%s]",
                     res.path,
                     res.syscall_errno == 0 ? "SUCCESS" : strerror(res.syscall_errno));
            hits.push_back(buf);
        }
    }
    return hits;
}

// =============================================================================
// 10. Function interposition detection via dladdr
//
//     If a library was LD_PRELOADed or RTLD_INTERPOSEd, dlsym(RTLD_DEFAULT)
//     returns the interposer's address instead of libc's.
//     dladdr on that address tells us which .so "owns" it.
//     If a critical libc symbol is "owned" by a non-system library → hook.
// =============================================================================

static std::vector<std::string> check_function_interposition() {
    std::vector<std::string> hits;
    const char* funcs[] = {
        "open", "openat", "stat", "stat64",
        "opendir", "readdir", "readdir64",
        "getuid", "getgid", "getpid",
        "kill", "access", "fstatat64",
        nullptr
    };
    for (int i = 0; funcs[i]; i++) {
        void* sym = dlsym(RTLD_DEFAULT, funcs[i]);
        if (!sym) continue;
        Dl_info info{};
        if (!dladdr(sym, &info) || !info.dli_fname) continue;
        const char* fname = info.dli_fname;
        bool ok = strstr(fname, "/system/") || strstr(fname, "/apex/") ||
                  strstr(fname, "/bionic/") || strstr(fname, "/lib/") ||
                  strstr(fname, "linker");
        if (!ok) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s() owned by non-system lib: %s", funcs[i], fname);
            hits.push_back(buf);
        }
    }
    return hits;
}

// =============================================================================
// 11. File descriptor scan
//
//     Enumerate /proc/self/fd and resolve each link. Flag FDs pointing to
//     root-daemon sockets, /data/adb paths, or APatch device nodes.
// =============================================================================

static std::vector<std::string> scan_file_descriptors() {
    std::vector<std::string> hits;
    const char* suspicious_fd[] = {
        "magisk", "zygisk", "ksu", "apatch", "apd", "ksud", "shamiko",
        "/data/adb", "/dev/kp", "/dev/apatch",
        nullptr
    };
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return hits;
    dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
        char link[PATH_MAX]{};
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len <= 0) continue;
        link[len] = '\0';
        std::string lower = str_lower(std::string(link));
        for (int i = 0; suspicious_fd[i]; i++) {
            if (lower.find(suspicious_fd[i]) != std::string::npos) {
                char buf[PATH_MAX + 32];
                snprintf(buf, sizeof(buf), "fd[%s] -> %s", entry->d_name, link);
                hits.push_back(buf);
                break;
            }
        }
    }
    closedir(dir);
    return hits;
}

// =============================================================================
// 12. /proc/net/unix socket scan (existing, slightly optimized)
// =============================================================================

static std::vector<std::string> scan_unix_sockets() {
    std::vector<std::string> hits;
    const char* patterns[] = {
        "@magisk", "/.magisk", "/magisk.", "zygisk", "ksu", "apatch",
        "apd", "ksud", "shamiko", nullptr
    };
    std::ifstream f("/proc/net/unix");
    if (!f.is_open()) return hits;
    std::string line;
    while (std::getline(f, line)) {
        std::string lower = str_lower(line);
        for (int i = 0; patterns[i]; i++) {
            if (lower.find(patterns[i]) != std::string::npos) {
                hits.push_back(line.substr(0, 120)); // cap length
                break;
            }
        }
    }
    return hits;
}

// =============================================================================
// 13. dl_iterate_phdr divergence
//
//     Manual mmap() injection (used by some Zygisk loaders) adds .so sections
//     to /proc/self/maps but does NOT register them with the linker, so they
//     won't appear in dl_iterate_phdr. We compare both lists to find "ghost" libs.
//
//     Approach:
//     - Collect all library paths from dl_iterate_phdr
//     - Scan /proc/self/maps for .so paths NOT in the linker list AND not system
//     - Those "ghost" entries were manually mapped (injected without dlopen)
// =============================================================================

static int phdr_callback(struct dl_phdr_info* info, size_t, void* data) {
    if (info->dlpi_name && info->dlpi_name[0] != '\0') {
        auto* set = reinterpret_cast<std::set<std::string>*>(data);
        set->insert(info->dlpi_name);
    }
    return 0;
}

static std::vector<std::string> find_ghost_libraries() {
    std::set<std::string> linker_libs;
    dl_iterate_phdr(phdr_callback, &linker_libs);

    std::vector<std::string> ghosts;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return ghosts;

    std::set<std::string> seen;
    std::string line;
    while (std::getline(maps, line)) {
        // Extract path
        size_t pos = 0;
        for (int f = 0; f < 5 && pos < line.size(); f++) {
            while (pos < line.size() && line[pos] == ' ') pos++;
            while (pos < line.size() && line[pos] != ' ') pos++;
        }
        while (pos < line.size() && line[pos] == ' ') pos++;
        if (pos >= line.size()) continue;
        std::string path = line.substr(pos);
        if (path.empty() || path[0] == '[') continue;
        if (path.find(".so") == std::string::npos) continue;
        if (seen.count(path)) continue;
        seen.insert(path);

        // Skip system paths
        if (is_system_path(path)) continue;
        // Skip known app paths
        if (path.find("/data/app/") != std::string::npos) continue;
        if (path.find("rootdetector") != std::string::npos) continue;

        // Not registered with the linker → ghost injection
        if (linker_libs.find(path) == linker_libs.end()) {
            // Double-check it has suspicious name to reduce noise
            std::string lower = str_lower(path);
            for (int i = 0; SUSPICIOUS_PATTERNS[i]; i++) {
                if (lower.find(SUSPICIOUS_PATTERNS[i]) != std::string::npos) {
                    ghosts.push_back("GHOST: " + path);
                    break;
                }
            }
        }
    }
    return ghosts;
}

// =============================================================================
// 14. /proc/self/status — check for UID=0, suspicious security attrs
// =============================================================================

static std::string get_status_field(const char* field) {
    std::ifstream f("/proc/self/status");
    std::string line;
    size_t flen = strlen(field);
    while (std::getline(f, line)) {
        if (line.compare(0, flen, field) == 0) {
            std::string v = line.substr(flen);
            v.erase(0, v.find_first_not_of(" \t:"));
            return v;
        }
    }
    return "";
}

// =============================================================================
// Kernel version string — /proc/version is kernel-owned, cannot be spoofed by userspace.
// Custom root kernels (KernelSU, Kitsune, APatch) often leave strings here.
// =============================================================================
static std::vector<std::string> check_kernel_version_strings() {
    std::vector<std::string> hits;
    std::ifstream f("/proc/version");
    if (!f.is_open()) return hits;
    std::string ver;
    std::getline(f, ver);
    f.close();
    if (ver.empty()) return hits;

    static const char* kSuspect[] = {
        "ksu", "kernelsu", "kitsune", "apatch",
        "magisk", "userdebug", "test-keys",
        nullptr
    };
    std::string lower = ver;
    for (char& c : lower) c = (char)tolower((unsigned char)c);
    for (int i = 0; kSuspect[i]; i++) {
        if (lower.find(kSuspect[i]) != std::string::npos)
            hits.push_back(std::string(kSuspect[i]) + " in /proc/version: " + ver);
    }
    return hits;
}

// =============================================================================
// /sbin path scan — direct syscall, bypasses any in-process libc hooks
// Kitsune Mask DenyList may leave /sbin accessible when stock Magisk DenyList does not.
// =============================================================================
static std::vector<std::string> scan_sbin_paths() {
    static const char* kSbinPaths[] = {
        "/sbin/su",
        "/sbin/magisk",
        "/sbin/magisk64",
        "/sbin/magisk32",
        "/sbin/.magisk",
        "/sbin/magiskpolicy",
        "/sbin/magiskinit",
        "/sbin/kitsune",
        "/sbin/ksud",
        "/sbin/apd",
        nullptr
    };
    std::vector<std::string> hits;
    for (int i = 0; kSbinPaths[i]; i++) {
        if (file_exists_syscall(kSbinPaths[i]))
            hits.push_back(kSbinPaths[i]);
    }
    return hits;
}

// =============================================================================
// Process table scan via /proc/<pid>/comm + cmdline
//
// DenyList = mount namespace isolation ONLY. It does NOT hide processes.
// magiskd/ksud/apd appear in /proc regardless of DenyList or Shamiko.
// /proc/<pid>/comm is readable by untrusted_app per Android SELinux policy.
// =============================================================================
static std::vector<std::string> scan_proc_for_root_daemons() {
    std::vector<std::string> hits;

    static const char* kRootComms[] = {
        "magiskd", "magisk32", "magisk64", "magiskinit", "magiskpolicy",
        "ksud", "ksumd",
        "apd", "kpatch",
        nullptr
    };

    DIR* dir = opendir("/proc");
    if (!dir) return hits;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        const char* pid = ent->d_name;
        bool found_this_pid = false;

        // 1. /proc/<pid>/comm — short name (≤15 chars), exact process name
        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/comm", pid);
        char comm[32] = {};
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            read(fd, comm, sizeof(comm) - 1);
            close(fd);
            for (int i = 0; comm[i]; i++) if (comm[i] == '\n') { comm[i] = 0; break; }
            for (int k = 0; kRootComms[k]; k++) {
                if (strcmp(comm, kRootComms[k]) == 0) {
                    hits.push_back(std::string(comm) + " (PID " + pid + ")");
                    found_this_pid = true;
                    break;
                }
            }
        }

        if (found_this_pid) continue;

        // 2. /proc/<pid>/cmdline — full argv[0]
        snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
        char cmdline[256] = {};
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
            if (n > 0) {
                for (ssize_t i = 0; i < n; i++) if (cmdline[i] == '\0') cmdline[i] = ' ';
                std::string cmd(cmdline, n);
                std::string lower = cmd;
                for (char& c : lower) c = (char)tolower((unsigned char)c);
                if (lower.find("magiskd") != std::string::npos ||
                    lower.find("magisk --") != std::string::npos ||
                    lower.find("/magisk64") != std::string::npos ||
                    lower.find("/magisk32") != std::string::npos) {
                    hits.push_back("PID " + std::string(pid) + ": " + cmd.substr(0, 60));
                    found_this_pid = true;
                }
            }
        }

        if (found_this_pid) continue;

        // 3. /proc/<pid>/exe — kernel resolves this symlink in ROOT mount namespace,
        // NOT our DenyList-isolated namespace. Even if /sbin is unmounted from our
        // namespace, readlink here still returns the original path like /sbin/magisk64.
        // Also catches processes that renamed comm/cmdline to evade detection.
        snprintf(path, sizeof(path), "/proc/%s/exe", pid);
        char exe[256] = {};
        ssize_t elen = readlink(path, exe, sizeof(exe) - 1);
        if (elen > 0) {
            std::string exe_str(exe, elen);
            std::string lower = exe_str;
            for (char& c : lower) c = (char)tolower((unsigned char)c);
            if (lower.find("magisk") != std::string::npos ||
                lower.find("kitsune") != std::string::npos ||
                lower.find("ksud") != std::string::npos ||
                lower.find("apd") != std::string::npos) {
                hits.push_back("exe=" + exe_str + " (PID " + std::string(pid) + ")");
            }
        }
    }
    closedir(dir);
    return hits;
}

// =============================================================================
// Environment variable scan — check /proc/self/environ for root-set vars.
// Zygisk/Magisk might leave traces in env before DenyList cleanup.
// =============================================================================
static std::vector<std::string> scan_environ_for_root() {
    std::vector<std::string> hits;
    int fd = open("/proc/self/environ", O_RDONLY);
    if (fd < 0) return hits;
    char buf[8192] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return hits;

    static const char* kEnvKeywords[] = {
        "MAGISK", "ZYGISK", "KITSUNE", "KSU", "APATCH", nullptr
    };
    size_t i = 0;
    while (i < (size_t)n) {
        const char* entry = buf + i;
        size_t len = strnlen(entry, (size_t)n - i);
        if (len > 0) {
            std::string s(entry, len);
            std::string upper = s;
            for (char& c : upper) c = (char)toupper((unsigned char)c);
            for (int k = 0; kEnvKeywords[k]; k++) {
                if (upper.find(kEnvKeywords[k]) != std::string::npos) {
                    hits.push_back(s);
                    break;
                }
            }
        }
        i += len + 1;
    }
    return hits;
}

// =============================================================================
// JNI bridge — aggregate all results
// =============================================================================

extern "C" {

JNIEXPORT jobjectArray JNICALL
Java_id_jayatech_rootdetector_detector_NativeDetector_nativeScan(JNIEnv* env, jobject) {
    std::vector<std::string> results;

    // --- Maps: suspicious libs (filtered for system paths) ---
    for (auto& s : scan_maps_suspicious_libs())
        results.push_back("MAPS:" + s);

    // --- Anonymous RWX pages ---
    for (auto& s : find_anonymous_rwx_mappings())
        results.push_back("ANON_RWX:" + s);

    // --- Ghost libraries (mmap'd without dlopen) ---
    for (auto& s : find_ghost_libraries())
        results.push_back("GHOST_LIB:" + s);

    // --- KernelSU syscall probe ---
    if (probe_kernelsu_syscall_safe())
        results.push_back("KSU_SYSCALL:syscall 0xDEADBEEF responded — KernelSU kernel hook active");

    // --- APatch kernel device ---
    if (probe_apatch())
        results.push_back("APATCH_DEV:/dev/kp or /dev/apatch found");

    // --- Already-loaded root libs (dlopen RTLD_NOLOAD) ---
    for (auto& s : probe_loaded_libs())
        results.push_back("LOADED_LIB:" + s);

    // --- Symbol probe (injected frameworks export known symbols, incl. Frida gadget) ---
    for (auto& s : probe_root_symbols())
        results.push_back("ROOT_SYMBOL:" + s);

    // --- Frida port 27042 (catches renamed standalone frida-server) ---
    if (probe_frida_port())
        results.push_back("FRIDA_PORT:TCP port 27042 (0x69A2) is open — frida-server running (possibly renamed)");

    // --- /sbin path scan via direct syscall (bypasses Zygisk libc hooks) ---
    // Kitsune Mask DenyList may leave /sbin unmounted in app namespace unlike stock Magisk.
    for (auto& s : scan_sbin_paths())
        results.push_back("SBIN_PATH:" + s);

    // --- Process table scan — DenyList hides mounts, NOT processes ---
    // magiskd/ksud/apd remain visible in /proc regardless of DenyList or Shamiko.
    for (auto& s : scan_proc_for_root_daemons())
        results.push_back("ROOT_PROC:" + s);

    // --- Environment variable scan ---
    for (auto& s : scan_environ_for_root())
        results.push_back("ROOT_ENV:" + s);

    // --- Kernel version strings — kernel-owned, zero userspace spoofability ---
    for (auto& s : check_kernel_version_strings())
        results.push_back("KERNEL_STR:" + s);

    // --- Capability elevation ---
    std::string cap_eff;
    if (has_elevated_capabilities(cap_eff))
        results.push_back("CAPABILITY:CapEff=" + cap_eff + " (non-zero — process has elevated Linux capabilities)");

    // --- UID = 0 via direct syscall ---
    if (is_root_uid())
        results.push_back("UID_ZERO:process is running as UID 0 (root) via kernel syscall");

    // --- getuid() consistency (libc vs syscall) ---
    long uid_sys; uid_t uid_lib;
    if (check_uid_consistency(uid_sys, uid_lib)) {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "UID_HOOK:getuid() libc=%u but SYS_getuid=%ld — libc is hooked", uid_lib, uid_sys);
        results.push_back(buf);
    }

    // --- File hiding detection ---
    for (auto& s : detect_file_hiding())
        results.push_back("FILE_HIDE:" + s);

    // --- Function interposition (LD_PRELOAD/RTLD_INTERPOSE) ---
    for (auto& s : check_function_interposition())
        results.push_back("FUNC_HOOK:" + s);

    // --- FD scan ---
    for (auto& s : scan_file_descriptors())
        results.push_back("FD:" + s);

    // --- Unix sockets ---
    for (auto& s : scan_unix_sockets())
        results.push_back("UNIX_SOCKET:" + s);

    jclass strCls = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray((jsize)results.size(), strCls, env->NewStringUTF(""));
    for (int i = 0; i < (int)results.size(); i++)
        env->SetObjectArrayElement(arr, i, env->NewStringUTF(results[i].c_str()));
    return arr;
}

JNIEXPORT jboolean JNICALL
Java_id_jayatech_rootdetector_detector_NativeDetector_nativeProbeKernelSU(JNIEnv*, jobject) {
    return probe_kernelsu_syscall_safe() ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
