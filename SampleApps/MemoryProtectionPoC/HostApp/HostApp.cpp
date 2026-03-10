// HostApp.cpp : Memory Protection PoC - Host Application (VTL0)
// This application demonstrates VBS enclave memory isolation by:
// - Storing public data in VTL0 (host) memory
// - Storing secret data in VTL1 (enclave) protected memory
// - Running indefinitely to allow external memory scanning

#include <iostream>
#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>
#include <VbsEnclave\HostApp\Stubs\Trusted.h>
#include <windows.h>

// Public data in VTL0 - THIS SHOULD BE READABLE by attacker
// Using volatile to prevent compiler optimizations and ensure it stays in memory
volatile wchar_t g_public_data[] = L"PUBLIC_DATA_READABLE_123456";

int main()
{
    std::wcout << L"=== VBS Enclave Memory Protection PoC ===" << std::endl;
    std::wcout << std::endl;

    /******************************* Public Data Info *******************************/

    // Use VirtualAlloc to ensure memory is committed and readable
    const wchar_t publicString[] = L"PUBLIC_DATA_READABLE_123456_HEAP";
    wchar_t* heapPublicData = (wchar_t*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (heapPublicData != NULL) {
        wcscpy_s(heapPublicData, 64, publicString);
        // Touch the memory to ensure it's committed
        heapPublicData[0] = heapPublicData[0];
    }

    std::wcout << L"[VTL0] Process ID: " << GetCurrentProcessId() << std::endl;
    std::wcout << L"[VTL0] Public data (global) address: 0x" << std::hex << (uint64_t)&g_public_data << std::dec << std::endl;
    if (heapPublicData) {
        std::wcout << L"[VTL0] Public data (VirtualAlloc) address: 0x" << std::hex << (uint64_t)heapPublicData << std::dec << std::endl;
        std::wcout << L"[VTL0] Public data content: " << heapPublicData << std::endl;
    }
    std::wcout << std::endl;

    /******************************* Enclave Setup *******************************/
    
    try {
        std::wcout << L"[VTL0] Loading VBS Enclave..." << std::endl;

        // Create app+user enclave identity
        auto ownerId = veil::vtl0::appmodel::owner_id();

        // Load enclave with debug flag for Debug builds
#ifdef _DEBUG
        constexpr int EnclaveCreate_Flags = ENCLAVE_VBS_FLAG_DEBUG;
#else
        constexpr int EnclaveCreate_Flags = 0;
        static_assert((EnclaveCreate_Flags & ENCLAVE_VBS_FLAG_DEBUG) == 0, 
                      "ERROR: Do not use _DEBUG flag for retail builds");
#endif

        // Memory allocation must match enclave configuration (512MB)
        auto enclave = veil::vtl0::enclave::create(
            ENCLAVE_TYPE_VBS, 
            ownerId, 
            EnclaveCreate_Flags, 
            veil::vtl0::enclave::megabytes(512)
        );
        
        veil::vtl0::enclave::load_image(enclave.get(), L"Trusted.dll");
        veil::vtl0::enclave::initialize(enclave.get(), 1);

        // Register framework callbacks
        veil::vtl0::enclave_api::register_callbacks(enclave.get());

        // Initialize enclave interface (PoCEnclave is codegen generated)
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::PoCEnclave(enclave.get());
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        std::wcout << L"[VTL0] Enclave loaded successfully!" << std::endl;
        std::wcout << std::endl;

        /******************************* Call Enclave *******************************/

        std::wcout << L"[VTL0] Calling enclave to store secret..." << std::endl;
        
        // Store secret in VTL1 and get back the address
        uint64_t secretAddress = enclaveInterface.StoreSecret(L"SECRET_IN_VTL1_987654");
        
        std::wcout << L"[VTL1] Secret data address: 0x" << std::hex << secretAddress << std::dec << std::endl;
        
        // Verify we can read it back through the enclave interface
        auto secretRead = enclaveInterface.ReadSecret();
        std::wcout << L"[VTL1] Secret verified via enclave: " << secretRead << std::endl;
        std::wcout << std::endl;

        /******************************* Instructions *******************************/

        std::wcout << L"======================================" << std::endl;
        std::wcout << L"PoC is ready for memory scanning test!" << std::endl;
        std::wcout << L"======================================" << std::endl;
        std::wcout << std::endl;
        std::wcout << L"Run the memory scanner in another terminal:" << std::endl;
        if (heapPublicData) {
            std::wcout << L"  MemoryScanner.exe " << GetCurrentProcessId() 
                       << L" 0x" << std::hex << (uint64_t)heapPublicData 
                       << L" 0x" << secretAddress << std::dec << std::endl;
            std::wcout << std::endl;
            std::wcout << L"Expected results:" << std::endl;
            std::wcout << L"  - VTL0 address (VirtualAlloc): Scanner WILL read: \"" << heapPublicData << L"\"" << std::endl;
            std::wcout << L"  - VTL1 address: Scanner CANNOT read (protected by VBS)" << std::endl;
        }
        std::wcout << std::endl;
        std::wcout << L"Press Ctrl+C to exit..." << std::endl;

        /******************************* Keep Running *******************************/

        // Run indefinitely to allow memory scanning
        while (true) {
            Sleep(1000);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
