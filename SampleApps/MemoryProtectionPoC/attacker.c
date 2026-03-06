// attacker.c - Memory Scanner PoC
// This program attempts to read memory from a running VBS enclave PoC process
// It demonstrates that VTL0 memory is readable but VTL1 (enclave) memory is protected
//
// Compile on Windows: cl.exe attacker.c /Fe:MemoryScanner.exe
// Usage: MemoryScanner.exe <PID> <vtl0_address> <vtl1_address>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define SEARCH_PATTERN_PUBLIC L"PUBLIC_DATA_READABLE"
#define SEARCH_PATTERN_SECRET L"SECRET_IN_VTL1"
#define MAX_READ_SIZE 1024

// Try to read memory at a specific address
BOOL TryDirectRead(HANDLE hProcess, UINT64 address, const wchar_t* label) {
    wchar_t buffer[MAX_READ_SIZE] = {0};
    SIZE_T bytesRead = 0;
    
    printf("\n[DIRECT READ] Attempting to read %S at 0x%llX...\n", label, address);
    
    if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, sizeof(buffer), &bytesRead)) {
        if (bytesRead > 0) {
            printf("[SUCCESS] Read %llu bytes from 0x%llX\n", (unsigned long long)bytesRead, address);
            printf("[CONTENT] First 128 chars: %.128S\n", buffer);
            return TRUE;
        }
    }
    
    DWORD error = GetLastError();
    printf("[FAILED] Cannot read from 0x%llX - Error: %lu", address, error);
    
    switch(error) {
        case ERROR_PARTIAL_COPY:
            printf(" (ERROR_PARTIAL_COPY - Only part of memory is accessible)\n");
            break;
        case ERROR_NOACCESS:
            printf(" (ERROR_NOACCESS - Invalid memory address)\n");
            break;
        case ERROR_ACCESS_DENIED:
            printf(" (ERROR_ACCESS_DENIED - Access denied)\n");
            break;
        default:
            printf("\n");
            break;
    }
    
    return FALSE;
}

// Scan memory regions looking for patterns
void ScanMemoryRegions(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    MEMORY_BASIC_INFORMATION memInfo;
    UINT64 address = 0;
    SIZE_T bytesRead;
    BOOL foundPublic = FALSE;
    BOOL foundSecret = FALSE;
    int regionsScanned = 0;
    int readableRegions = 0;
    
    GetSystemInfo(&sysInfo);
    
    printf("\n========================================\n");
    printf("MEMORY SCAN MODE\n");
    printf("========================================\n");
    printf("Scanning memory regions for patterns...\n");
    printf("Looking for: '%S' and '%S'\n\n", 
           SEARCH_PATTERN_PUBLIC, SEARCH_PATTERN_SECRET);
    
    address = (UINT64)sysInfo.lpMinimumApplicationAddress;
    
    while (address < (UINT64)sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &memInfo, sizeof(memInfo)) == 0) {
            break;
        }
        
        // Only scan committed, readable memory
        if (memInfo.State == MEM_COMMIT && 
            (memInfo.Protect == PAGE_READWRITE || 
             memInfo.Protect == PAGE_READONLY ||
             memInfo.Protect == PAGE_EXECUTE_READ ||
             memInfo.Protect == PAGE_EXECUTE_READWRITE)) {
            
            regionsScanned++;
            
            // Allocate buffer for this region (limit to 1MB per region)
            SIZE_T regionSize = memInfo.RegionSize;
            if (regionSize > 1024 * 1024) {
                regionSize = 1024 * 1024;
            }
            
            wchar_t* buffer = (wchar_t*)malloc(regionSize);
            if (buffer != NULL) {
                if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, regionSize, &bytesRead)) {
                    readableRegions++;
                    
                    // Search for patterns in the buffer
                    SIZE_T wcharCount = bytesRead / sizeof(wchar_t);
                    for (SIZE_T i = 0; i < wcharCount - 20; i++) {
                        if (!foundPublic && wcsncmp(&buffer[i], SEARCH_PATTERN_PUBLIC, wcslen(SEARCH_PATTERN_PUBLIC)) == 0) {
                            printf("[FOUND] PUBLIC pattern at 0x%llX\n", (UINT64)memInfo.BaseAddress + (i * sizeof(wchar_t)));
                            printf("        Content: %.64S\n", &buffer[i]);
                            foundPublic = TRUE;
                        }
                        if (!foundSecret && wcsncmp(&buffer[i], SEARCH_PATTERN_SECRET, wcslen(SEARCH_PATTERN_SECRET)) == 0) {
                            printf("[FOUND] SECRET pattern at 0x%llX\n", (UINT64)memInfo.BaseAddress + (i * sizeof(wchar_t)));
                            printf("        Content: %.64S\n", &buffer[i]);
                            foundSecret = TRUE;
                        }
                    }
                }
                free(buffer);
            }
        }
        
        address = (UINT64)memInfo.BaseAddress + memInfo.RegionSize;
    }
    
    printf("\n--- Scan Summary ---\n");
    printf("Regions scanned: %d\n", regionsScanned);
    printf("Readable regions: %d\n", readableRegions);
    printf("PUBLIC pattern found: %s\n", foundPublic ? "YES" : "NO");
    printf("SECRET pattern found: %s\n", foundSecret ? "NO (VTL1 PROTECTED)" : "YES (PROTECTION FAILED!)");
}

int main(int argc, char* argv[]) {
    DWORD pid;
    UINT64 vtl0Address = 0;
    UINT64 vtl1Address = 0;
    HANDLE hProcess;
    
    printf("========================================\n");
    printf("VBS Enclave Memory Scanner PoC\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <PID> [vtl0_address] [vtl1_address]\n", argv[0]);
        printf("\nModes:\n");
        printf("  1. Memory scan only:    %s <PID>\n", argv[0]);
        printf("  2. Direct read + scan:  %s <PID> <vtl0_addr> <vtl1_addr>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s 1234 0x12345678 0xABCDEF00\n", argv[0]);
        return 1;
    }
    
    // Parse arguments
    pid = atoi(argv[1]);
    if (argc >= 3) {
        vtl0Address = strtoull(argv[2], NULL, 0);
    }
    if (argc >= 4) {
        vtl1Address = strtoull(argv[3], NULL, 0);
    }
    
    printf("Target Process ID: %lu\n", pid);
    if (vtl0Address) printf("VTL0 Address: 0x%llX\n", vtl0Address);
    if (vtl1Address) printf("VTL1 Address: 0x%llX\n", vtl1Address);
    
    // Open target process
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("\n[ERROR] Cannot open process %lu - Error: %lu\n", pid, GetLastError());
        printf("Make sure:\n");
        printf("  1. The target process is running\n");
        printf("  2. You have sufficient privileges (run as Administrator)\n");
        return 1;
    }
    
    printf("[SUCCESS] Process handle obtained\n");
    
    // Mode 1: Direct address reads (if addresses provided)
    if (vtl0Address != 0 && vtl1Address != 0) {
        printf("\n========================================\n");
        printf("DIRECT READ MODE\n");
        printf("========================================\n");
        
        BOOL vtl0Success = TryDirectRead(hProcess, vtl0Address, L"VTL0 (Host Memory)");
        BOOL vtl1Success = TryDirectRead(hProcess, vtl1Address, L"VTL1 (Enclave Memory)");
        
        printf("\n--- Direct Read Results ---\n");
        printf("VTL0 Read: %s\n", vtl0Success ? "SUCCESS (Expected)" : "FAILED (Unexpected)");
        printf("VTL1 Read: %s\n", vtl1Success ? "FAILED - VBS PROTECTION BYPASSED!" : "BLOCKED (Expected - VBS Protected)");
    }
    
    // Mode 2: Memory scan
    ScanMemoryRegions(hProcess);
    
    printf("\n========================================\n");
    printf("CONCLUSION\n");
    printf("========================================\n");
    printf("If VBS enclave protection is working correctly:\n");
    printf("  - VTL0 data SHOULD be readable\n");
    printf("  - VTL1 data should NOT be readable\n");
    printf("  - Memory scan should find PUBLIC but not SECRET\n");
    printf("========================================\n");
    
    CloseHandle(hProcess);
    return 0;
}
