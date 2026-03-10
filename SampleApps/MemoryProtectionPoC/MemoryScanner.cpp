// attacker.c - Simple Memory Read Test
// Demonstrates VBS Enclave memory protection by attempting to read process memory
// - Normal processes: Read succeeds
// - VBS Enclave processes: Read fails with ERROR_PARTIAL_COPY (299)
//
// Compile: cl.exe attacker.c /Fe:MemoryScanner.exe
// Usage: MemoryScanner.exe <PID> <address>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_READ_SIZE 4096

// Try to read memory at a specific address
BOOL TestMemoryRead(HANDLE hProcess, UINT64 address) {
    char buffer[MAX_READ_SIZE] = {0};
    SIZE_T bytesRead = 0;

    printf("\n======================================\n");
    printf("Testing memory read at: 0x%llX\n", address);
    printf("======================================\n\n");

    if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, MAX_READ_SIZE, &bytesRead)) {
        printf("[SUCCESS] Read %llu bytes\n", (unsigned long long)bytesRead);
        printf("[RESULT] Process memory is READABLE\n");
        printf("[DATA] First 64 bytes: %.64s\n", buffer);
        return TRUE;
    } else {
        DWORD error = GetLastError();
        printf("[FAILED] Cannot read memory\n");
        printf("[ERROR CODE] %lu\n", error);

        if (error == 299) {
            printf("[RESULT] ERROR_PARTIAL_COPY (299) - VBS PROTECTION ACTIVE\n");
        } else if (error == 998) {
            printf("[RESULT] ERROR_NOACCESS (998) - Invalid address\n");
        } else if (error == 5) {
            printf("[RESULT] ERROR_ACCESS_DENIED (5) - Permission denied\n");
        } else {
            printf("[RESULT] Other error\n");
        }
        return FALSE;
    }
}

int main(int argc, char* argv[]) {
    DWORD pid;
    UINT64 address = 0;
    HANDLE hProcess;

    printf("========================================\n");
    printf("VBS Enclave Memory Protection Test\n");
    printf("========================================\n\n");

    if (argc < 3) {
        printf("Usage: %s <PID> <address>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s 1234 0x12345678\n", argv[0]);
        printf("\nTest:\n");
        printf("  1. Run NormalApp.exe (no VBS) - memory read should SUCCEED\n");
        printf("  2. Run HostApp.exe (with VBS) - memory read should FAIL with error 299\n");
        return 1;
    }

    pid = atoi(argv[1]);
    address = strtoull(argv[2], NULL, 0);

    printf("Target Process ID: %lu\n", pid);
    printf("Target Address: 0x%llX\n", address);

    // Open process
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("\n[ERROR] Cannot open process: %lu\n", GetLastError());
        printf("Make sure you run as Administrator\n");
        return 1;
    }

    printf("[OK] Process handle obtained\n");

    // Test memory read
    BOOL success = TestMemoryRead(hProcess, address);

    printf("\n========================================\n");
    printf("CONCLUSION:\n");
    printf("========================================\n");
    if (success) {
        printf("[SUCCESS] Normal process (NO VBS protection)\n");
        printf("This process memory CAN be read by attackers!\n");
    } else {
        printf("[PROTECTED] VBS Enclave is ACTIVE!\n");
        printf("Memory is protected from external access.\n");
    }
    printf("========================================\n");

    CloseHandle(hProcess);
    return 0;
}
