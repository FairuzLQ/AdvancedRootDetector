// libFuzzer harness for the pure native rules in signatures.h.
// These parse untrusted text (/proc files, mount tables, kernel strings) inside the host
// app's process — a crash or hang here is a crash or hang in the app using the library.
//
// Build: clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined fuzz_signatures.cpp
#include "../../rootdetector/src/main/cpp/signatures.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string s(reinterpret_cast<const char*>(data), size);
    std::string l = sig::lower(s);

    (void)sig::contains_token(l, "ksu");
    (void)sig::maps_path(s);
    (void)sig::maps_perms(s);
    (void)sig::is_suspicious_maps_line(s);
    (void)sig::is_root_unix_socket(s);
    (void)sig::kernel_version_hits(s);
    (void)sig::is_suspicious_fd_target(s);
    (void)sig::is_foreign_symbol_owner(s.c_str());
    (void)sig::tcp_local_port_is(s, "69A2");
    (void)sig::classify_uid0_status(s, "123");
    (void)sig::status_int_field(s, "Uid");
    (void)sig::status_name(s);
    (void)sig::jni_safe(s);

    // ELF segment mapping with fuzzer-chosen segments and address
    if (size >= 40) {
        auto rd = [&](size_t o) { unsigned long long v = 0; memcpy(&v, data + o, 8); return v; };
        std::vector<sig::LoadSegment> segs = { { rd(0), rd(8), rd(16), rd(24) } };
        unsigned long long off = 0;
        (void)sig::vaddr_to_file_offset(segs, rd(32), 16, off);
    }
    return 0;
}
