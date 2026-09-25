// Pure string-matching rules used by root_detector.cpp.
//
// No Android/JNI dependencies: the same header is compiled into the host-side lab
// (lab/native) and run against fixture files, so every rule here is regression-tested
// for both detection and false positives.
//
// FALSE POSITIVE rule of thumb: short keywords ("ksu", "apd", "kali") are matched as whole
// tokens, never as substrings — "checksum" contains "ksu".
#pragma once

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace sig {

inline std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

// True if `token` (lower-case) occurs in `hay_lower` bounded by non-alphanumerics.
inline bool contains_token(const std::string& hay_lower, const char* token) {
    const size_t tlen = strlen(token);
    if (tlen == 0) return false;
    size_t pos = 0;
    while ((pos = hay_lower.find(token, pos)) != std::string::npos) {
        bool before_ok = pos == 0 || !isalnum((unsigned char)hay_lower[pos - 1]);
        size_t end = pos + tlen;
        bool after_ok = end >= hay_lower.size() || !isalnum((unsigned char)hay_lower[end]);
        if (before_ok && after_ok) return true;
        pos++;
    }
    return false;
}

// -----------------------------------------------------------------------------
// /proc/self/maps
// -----------------------------------------------------------------------------

// Pathname column of a maps line ("" for anonymous mappings).
inline std::string maps_path(const std::string& line) {
    size_t pos = 0;
    for (int fields = 0; fields < 5 && pos < line.size(); fields++) {
        while (pos < line.size() && line[pos] == ' ') pos++;
        while (pos < line.size() && line[pos] != ' ') pos++;
    }
    while (pos < line.size() && line[pos] == ' ') pos++;
    return pos < line.size() ? line.substr(pos) : "";
}

static const char* const SYSTEM_PREFIXES[] = {
    "/system/", "/apex/", "/vendor/", "/product/", "/odm/",
    "/data/dalvik-cache/", "/data/app/", nullptr
};

inline bool is_system_path(const std::string& path) {
    for (int i = 0; SYSTEM_PREFIXES[i]; i++)
        if (path.compare(0, strlen(SYSTEM_PREFIXES[i]), SYSTEM_PREFIXES[i]) == 0) return true;
    return false;
}

// Substring-safe patterns (long / distinctive).
static const char* const SUSPICIOUS_PATTERNS[] = {
    "magisk", "zygisk", "shamiko", "lspd", "lspatch",
    "xposed", "riru", "frida", "objection", "apatch",
    "rezygisk", "zygnext", "dreamland", "pine_bridge", "kernelsu",
    nullptr
};
// Short patterns that must be whole tokens.
static const char* const SUSPICIOUS_TOKENS[] = { "ksu", nullptr };

inline bool has_suspicious_name(const std::string& text_lower) {
    for (int i = 0; SUSPICIOUS_PATTERNS[i]; i++)
        if (text_lower.find(SUSPICIOUS_PATTERNS[i]) != std::string::npos) return true;
    for (int i = 0; SUSPICIOUS_TOKENS[i]; i++)
        if (contains_token(text_lower, SUSPICIOUS_TOKENS[i])) return true;
    return false;
}

// Permissions column (2nd field) of a maps line, e.g. "r-xp". Address width varies
// (8–12+ hex digits), so it must be parsed, not read at a fixed offset.
inline std::string maps_perms(const std::string& line) {
    size_t p = line.find(' ');
    if (p == std::string::npos) return "";
    while (p < line.size() && line[p] == ' ') p++;
    size_t e = line.find(' ', p);
    return line.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

inline bool ends_with(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

// Code-carrying mapping: executable, a code file, or a named anon/memfd region.
// Plain data files the HOST app maps (databases, caches) are ignored — their names are
// chosen by the app ("ksu_ui_cache.bin", "magisk_check.db") and prove nothing.
inline bool is_code_mapping(const std::string& perms, const std::string& path_lower) {
    if (perms.size() >= 3 && perms[2] == 'x') return true;
    static const char* const code_ext[] = { ".so", ".dex", ".jar", ".apk", ".oat", ".odex", ".vdex", nullptr };
    for (int i = 0; code_ext[i]; i++)
        if (ends_with(path_lower, code_ext[i]) || path_lower.find(std::string(code_ext[i]) + " ") != std::string::npos ||
            path_lower.find(std::string(code_ext[i]) + "]") != std::string::npos) return true;
    return path_lower.rfind("[anon:", 0) == 0 || path_lower.rfind("/memfd:", 0) == 0;
}

// A maps line naming a root/hook library outside the signed system partitions.
inline bool is_suspicious_maps_line(const std::string& line) {
    std::string path = maps_path(line);
    if (!path.empty() && is_system_path(path)) return false;
    if (path == "[stack]" || path == "[heap]" || path == "[vvar]" ||
        path == "[vdso]" || path == "[vsyscall]") return false;
    std::string path_lower = lower(path);
    if (!is_code_mapping(maps_perms(line), path_lower)) return false;
    return has_suspicious_name(path_lower);
}

// -----------------------------------------------------------------------------
// /proc/net/unix
// -----------------------------------------------------------------------------

inline bool is_root_unix_socket(const std::string& line) {
    static const char* const patterns[] = {
        "@magisk", "/.magisk", "/magisk.", "zygisk", "apatch", "ksud", "shamiko", nullptr
    };
    std::string l = lower(line);
    for (int i = 0; patterns[i]; i++)
        if (l.find(patterns[i]) != std::string::npos) return true;
    return contains_token(l, "ksu") || contains_token(l, "apd");
}

// -----------------------------------------------------------------------------
// /proc/version
// -----------------------------------------------------------------------------

// Returns hits; custom-kernel hits are prefixed with "CUSTOM_KERNEL:".
inline std::vector<std::string> kernel_version_hits(const std::string& ver) {
    std::vector<std::string> hits;
    if (ver.empty()) return hits;
    static const char* const root_substrings[] = {
        "kernelsu", "kitsune", "apatch", "magisk", "userdebug", "test-keys", nullptr
    };
    static const char* const root_tokens[] = { "ksu", nullptr };
    static const char* const custom_kernels[] = {
        "blu-spark", "sultan", "arter97", "kali", "nexkernel",
        "proton", "darkhorse", "immensity", "elementalx", nullptr
    };
    std::string l = lower(ver);
    for (int i = 0; root_substrings[i]; i++)
        if (l.find(root_substrings[i]) != std::string::npos)
            hits.push_back(std::string(root_substrings[i]) + " in /proc/version: " + ver);
    for (int i = 0; root_tokens[i]; i++)
        if (contains_token(l, root_tokens[i]))
            hits.push_back(std::string(root_tokens[i]) + " in /proc/version: " + ver);
    for (int i = 0; custom_kernels[i]; i++)
        if (contains_token(l, custom_kernels[i]))
            hits.push_back(std::string("CUSTOM_KERNEL:") + custom_kernels[i] + " in /proc/version: " + ver);
    return hits;
}

// -----------------------------------------------------------------------------
// /proc/self/fd link targets
// -----------------------------------------------------------------------------

inline bool is_suspicious_fd_target(const std::string& link) {
    static const char* const always[] = {
        "/data/adb/", "/dev/kp", "/dev/apatch", "/memfd:frida", nullptr
    };
    // Root manager package names — matched against the package segment of /data/app paths
    // only (the Base64 install hash can contain short keywords by chance).
    static const char* const root_pkgs[] = {
        "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
        "io.github.rezygisk", "com.rifsxd.ksunext", "me.weishu.kernelsu",
        "com.sukisu.ultra", "me.bmax.apatch", "org.lsposed.manager", nullptr
    };
    static const char* const long_patterns[] = {
        "magiskd", "magisk64", "magisk32", "zygisk", "shamiko",
        "xposed", "lspatch", "frida-agent", nullptr
    };
    std::string l = lower(link);
    for (int i = 0; always[i]; i++)
        if (l.find(always[i]) != std::string::npos) return true;
    for (int i = 0; long_patterns[i]; i++)
        if (l.find(long_patterns[i]) != std::string::npos) return true;

    if (l.find("/data/app/") != std::string::npos) {
        size_t last_slash = l.rfind('/');
        size_t prev_slash = (last_slash != std::string::npos && last_slash > 0)
                            ? l.rfind('/', last_slash - 1) : std::string::npos;
        if (prev_slash != std::string::npos) {
            std::string seg = l.substr(prev_slash + 1, last_slash - prev_slash - 1);
            std::string pkg = seg.substr(0, seg.find('-'));
            for (int i = 0; root_pkgs[i]; i++)
                if (pkg == root_pkgs[i] || pkg.compare(0, strlen(root_pkgs[i]), root_pkgs[i]) == 0) return true;
            if (pkg.find("ksunext") != std::string::npos || pkg.find("kernelsu") != std::string::npos) return true;
        }
    }
    return false;
}

// -----------------------------------------------------------------------------
// dladdr owner of a libc symbol
// -----------------------------------------------------------------------------

// A libc symbol resolving into anything under /data (app lib dir, /data/local/tmp,
// /data/adb) or a memfd is an interposer. The old check accepted any path containing
// "/lib/", so a hook shipped in /data/app/<pkg>/lib/arm64/ was never reported.
inline bool is_foreign_symbol_owner(const char* fname) {
    if (!fname) return false;
    if (strncmp(fname, "/data/", 6) == 0 || strstr(fname, "memfd:")) return true;
    bool system = strstr(fname, "/system/") || strstr(fname, "/apex/") ||
                  strstr(fname, "/bionic/") || strstr(fname, "/lib/") ||
                  strstr(fname, "linker");
    return !system;
}

// -----------------------------------------------------------------------------
// /proc/<pid>/status — unknown UID-0 processes
// -----------------------------------------------------------------------------

inline int status_int_field(const std::string& status, const char* field) {
    std::string key = std::string("\n") + field + ":";
    size_t p = ("\n" + status).find(key);
    if (p == std::string::npos) return -1;
    const char* v = status.c_str() + p + strlen(field) + 1;  // p is offset in "\n"+status
    while (*v == '\t' || *v == ' ') v++;
    return atoi(v);
}

inline std::string status_name(const std::string& status) {
    std::string key = "Name:";
    size_t p = status.find(key);
    if (p == std::string::npos) return "";
    p += key.size();
    while (p < status.size() && (status[p] == '\t' || status[p] == ' ')) p++;
    size_t e = status.find('\n', p);
    return status.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

// Returns a description if this status block is an unexpected UID-0 process, else "".
inline std::string classify_uid0_status(const std::string& status, const std::string& pid) {
    static const char* const known[] = {
        "init", "kthreadd", "kswapd", "migration", "watchdog", "kworker",
        "ksoftirqd", "kcompactd", "rcu_", "netns", "khungtaskd", "oom_reaper",
        "writeback", "kdevtmpfs", "kblockd", "bioset", "kcopyd", "deferwq",
        "vmstat", "jbd2", "ext4-", "f2fs_", "zygote", "zygote64",
        "surfaceflinger", "system_server", "logd", "logcat",
        "vold", "netd", "adbd", "lmkd", "ueventd", "servicemanager",
        "hwservicemanager", "vndservicemanager", "audioserver", "mediaserver",
        "cameraserver", "drmserver", "wificond", "installd", "sdcard",
        "keystore", "gatekeeperd", "fingerprintd", "healthd", "thermal",
        "debuggerd", "tombstoned", "incidentd", "mdnsd", "rild",
        "dumpstate", "perfprofd", "storaged", "statsd",
        "ipv6proxy", "netmgrd", "qmuxd", "qti", "diag", "ims", "mcDriverDaemon",
        "ps", "ls", "sh", "cat", "grep", "getprop",  // transient shell commands
        nullptr
    };
    if (status_int_field(status, "Uid") != 0) return "";
    // Kernel threads (kthreadd = PID 2 and its children) are never userspace root daemons.
    // Their names ("irq/23-...", "cpuhp/0", "khugepaged") are not in the list above.
    int ppid = status_int_field(status, "PPid");
    if (pid == "2" || ppid == 2 || (ppid == 0 && pid != "1")) return "";
    std::string name = status_name(status);
    if (name.empty()) return "UID0 PID=" + pid + " (Name unreadable — suspicious)";
    if (name[0] == '[') return "";
    for (int k = 0; known[k]; k++)
        if (name.compare(0, strlen(known[k]), known[k]) == 0) return "";
    return "Unknown UID0 process: " + name + " (PID " + pid + ")";
}

// -----------------------------------------------------------------------------
// /proc/net/tcp[6]
// -----------------------------------------------------------------------------

// Line format: "  sl  local_address rem_address st ..." e.g.
//   "   0: 0100007F:69A2 00000000:0000 0A ..."
// The port is after the LAST ':' of the 2nd field. (The old parser took the first ':' in the
// line — the one after the slot number — so the Frida port was never matched.)
inline bool tcp_local_port_is(const std::string& line, const char* port_hex_upper) {
    size_t p = 0;
    while (p < line.size() && line[p] == ' ') p++;
    while (p < line.size() && line[p] != ' ') p++;          // skip "sl:"
    while (p < line.size() && line[p] == ' ') p++;
    size_t e = line.find(' ', p);
    std::string local = line.substr(p, e == std::string::npos ? std::string::npos : e - p);
    size_t colon = local.rfind(':');
    if (colon == std::string::npos) return false;
    std::string port = local.substr(colon + 1);
    for (auto& c : port) c = (char)toupper((unsigned char)c);
    return port == port_hex_upper;
}

// -----------------------------------------------------------------------------
// JNI string safety
// -----------------------------------------------------------------------------

// NewStringUTF requires Modified UTF-8. Evidence strings come from raw kernel/proc data
// (paths, cmdline, environ) and may hold arbitrary bytes or a UTF-8 sequence cut in half
// by a length cap; with CheckJNI (any debuggable app) that aborts the whole process.
// Keep printable ASCII, replace everything else with '?'.
inline std::string jni_safe(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s) r += (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    return r;
}

}  // namespace sig
