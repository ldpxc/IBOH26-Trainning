/**
 * Crackme / Protected License Checker - Simulated CTF Reverse Engineering Challenge
 * Contains multi-layered Anti-Analysis and Anti-Debugging defenses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <x86intrin.h>

// [Kỹ thuật 1]: Linux Anti-Debugging bằng ptrace(PTRACE_TRACEME) (CWE-656)
int anti_debug_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        // Có debugger đang gắn vào tiến trình
        return -1;
    }
    return 0;
}

// [Kỹ thuật 2]: Linux Anti-Debugging bằng kiểm tra TracerPid trong /proc (CWE-656)
int anti_debug_tracerpid(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;

    char line[256];
    int tracer_pid = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(&line[10]);
            break;
        }
    }
    fclose(fp);

    if (tracer_pid != 0) {
        // Phát hiện TracerPid > 0 (GDB / LLDB / Strace đang hook)
        return -1;
    }
    return 0;
}

// [Kỹ thuật 3]: CPU Cycle Timing Check bằng rdtsc (CWE-656)
int verify_serial_with_timing(const char *serial) {
    // Đo xung nhịp trước khi tính toán
    unsigned long long start_cycles = __rdtsc();

    unsigned int hash = 0x1337;
    for (size_t i = 0; i < strlen(serial); i++) {
        hash = (hash ^ serial[i]) * 0x5bd1e995;
    }

    // Đo xung nhịp sau khi tính toán
    unsigned long long end_cycles = __rdtsc();
    if ((end_cycles - start_cycles) > 0x100000) {
        // Nếu analyst đặt breakpoint hoặc step từng bước, cycle count sẽ vọt lên cao
        return 0;
    }

    return (hash == 0xdeadbeef);
}

int main(int argc, char **argv) {
    if (anti_debug_ptrace() < 0) {
        puts("[!] Debugger detected! Exiting...");
        exit(1);
    }

    if (anti_debug_tracerpid() < 0) {
        puts("[!] Process is being traced! Exiting...");
        exit(1);
    }

    if (argc < 2) {
        printf("Usage: %s <serial_key>\n", argv[0]);
        return 1;
    }

    if (verify_serial_with_timing(argv[1])) {
        puts("[+] Serial accepted! Flag: CTF{anti_debug_bypassed_successfully}");
    } else {
        puts("[-] Invalid serial.");
    }

    return 0;
}
