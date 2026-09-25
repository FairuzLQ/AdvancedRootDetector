// Host-side runner for the native rules in rootdetector/src/main/cpp/signatures.h.
// Usage: lab_native <scenario-dir>
// Prints one line per fired rule: "<rule-id>\t<evidence>". Missing fixture files are skipped.
#include "../../rootdetector/src/main/cpp/signatures.h"

#include <fstream>
#include <iostream>
#include <sstream>

static bool read_lines(const std::string& path, std::vector<std::string>& out) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) out.push_back(line);
    return true;
}

static void emit(const char* id, const std::string& ev) {
    std::cout << id << '\t' << sig::jni_safe(ev) << '\n';
}

int main(int argc, char** argv) {
    if (argc != 2) { std::cerr << "usage: lab_native <scenario-dir>\n"; return 2; }
    const std::string dir = argv[1];
    std::vector<std::string> lines;

    if (read_lines(dir + "/maps", lines))
        for (auto& l : lines) if (sig::is_suspicious_maps_line(l)) emit("native:maps", l);

    lines.clear();
    if (read_lines(dir + "/net_unix", lines))
        for (auto& l : lines) if (sig::is_root_unix_socket(l)) emit("native:unix_socket", l);

    lines.clear();
    if (read_lines(dir + "/proc_version", lines) && !lines.empty())
        for (auto& h : sig::kernel_version_hits(lines[0]))
            emit(h.rfind("CUSTOM_KERNEL:", 0) == 0 ? "native:custom_kernel" : "native:kernel_str", h);

    lines.clear();
    if (read_lines(dir + "/fd_links", lines))
        for (auto& l : lines) if (sig::is_suspicious_fd_target(l)) emit("native:fd", l);

    lines.clear();
    if (read_lines(dir + "/net_tcp", lines))
        for (auto& l : lines) if (sig::tcp_local_port_is(l, "69A2")) emit("native:frida_port", l);

    // proc_status: /proc/<pid>/status blocks separated by "----"
    lines.clear();
    if (read_lines(dir + "/proc_status", lines)) {
        lines.push_back("----");
        std::string block;
        for (auto& l : lines) {
            if (l == "----") {
                std::string pid;
                size_t p = block.find("Pid:");
                while (p != std::string::npos && p > 0 && block[p - 1] != '\n') p = block.find("Pid:", p + 1);
                if (p != std::string::npos) {
                    std::istringstream is(block.substr(p + 4));
                    is >> pid;
                }
                std::string hit = sig::classify_uid0_status(block, pid);
                if (!hit.empty()) emit("native:uid0", hit);
                block.clear();
            } else {
                block += l + "\n";
            }
        }
    }
    return 0;
}
