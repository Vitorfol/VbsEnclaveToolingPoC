// HostApp.cpp - VBS Enclave Memory Protection PoC
// Demonstrates that VBS Enclave memory (VTL1) is protected from external access

#include <iostream>
#include <veil\host\enclave_api.vtl0.h>
#include <VbsEnclave\HostApp\Stubs\Trusted.h>
#include <windows.h>

int main()
{
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"VBS Enclave Memory Protection PoC" << std::endl;
    std::wcout << L"========================================\n" << std::endl;

    std::wcout << L"[VTL0] Process ID: " << GetCurrentProcessId() << std::endl;

    try {
        std::wcout << L"[VTL0] Loading VBS Enclave...\n" << std::endl;

        auto ownerId = veil::vtl0::appmodel::owner_id();

#ifdef _DEBUG
        constexpr int EnclaveCreate_Flags = ENCLAVE_VBS_FLAG_DEBUG;
#else
        constexpr int EnclaveCreate_Flags = 0;
#endif

        auto enclave = veil::vtl0::enclave::create(
            ENCLAVE_TYPE_VBS, 
            ownerId, 
            EnclaveCreate_Flags, 
            veil::vtl0::enclave::megabytes(512)
        );

        veil::vtl0::enclave::load_image(enclave.get(), L"Trusted.dll");
        veil::vtl0::enclave::initialize(enclave.get(), 1);

        std::wcout << L"[VTL0] Enclave loaded successfully!\n" << std::endl;

        // Initialize enclave interface
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::PoCEnclave(enclave.get());
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        // Store secret in VTL1
        uint64_t secretAddress = enclaveInterface.StoreSecret(L"SECRET_IN_VTL1_PROTECTED");
        std::wstring secretData = enclaveInterface.ReadSecret();

        std::wcout << L"[VTL1] Secret Address: 0x" << std::hex << secretAddress << std::dec << std::endl;

        std::wcout << L"========================================" << std::endl;
        std::wcout << L"Test with MemoryScanner:" << std::endl;
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"  MemoryScanner.exe " << GetCurrentProcessId() 
                   << L" 0x" << std::hex << secretAddress << std::dec << L"\n" << std::endl;
        std::wcout << L"Press Ctrl+C to exit...\n" << std::endl;

        while (true) {
            Sleep(1000);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
