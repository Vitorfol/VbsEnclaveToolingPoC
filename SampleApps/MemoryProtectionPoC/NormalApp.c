// NormalApp.c - Normal process WITHOUT VBS protection
// Used as control to demonstrate that normal processes CAN be memory-scanned
//
// Compile: cl.exe NormalApp.c /Fe:NormalApp.exe

#include <windows.h>
#include <stdio.h>

// Simple test data
char g_testData[] = "This is test data in a normal process";

int main() {
    printf("========================================\n");
    printf("Normal Process (NO VBS Protection)\n");
    printf("========================================\n\n");
    
    printf("[PID] %lu\n", GetCurrentProcessId());
    printf("[ADDRESS] 0x%p\n", (void*)g_testData);
    printf("[DATA] %s\n\n", g_testData);
    
    printf("Test with MemoryScanner:\n");
    printf("  MemoryScanner.exe %lu 0x%p\n\n", GetCurrentProcessId(), (void*)g_testData);
    
    printf("Expected: SUCCESS (memory is readable)\n\n");
    printf("Press Ctrl+C to exit...\n");
    
    while (1) {
        Sleep(1000);
    }
    
    return 0;
}
