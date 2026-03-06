// TrustedImplementation.cpp : VTL1 Enclave Implementation
// This code runs in VTL1 (Virtual Trust Level 1) protected memory
// Memory here should NOT be readable by processes in VTL0, including the host app

#include "pch.h"
#include <VbsEnclave\Enclave\Implementation\Trusted.h>

// Global secret data stored in VTL1 protected memory
// This SHOULD NOT be readable by the attacker process
// Using static buffer instead of std::wstring to minimize DLL dependencies
static wchar_t g_secret_data[256] = {0};

// Implementation of StoreSecret - stores secret in VTL1 and returns address
uint64_t VbsEnclave::Trusted::Implementation::StoreSecret(_In_ const std::wstring& secret)
{
    // Store the secret in enclave memory using simple copy
    size_t length = secret.length();
    if (length >= 256) length = 255;

    for (size_t i = 0; i < length; i++)
    {
        g_secret_data[i] = secret[i];
    }
    g_secret_data[length] = L'\0';

    // Return the address of the secret data for testing purposes
    // Note: This breaks encapsulation but is necessary for the PoC to demonstrate
    // that VTL1 memory addresses cannot be read from VTL0
    return reinterpret_cast<uint64_t>(g_secret_data);
}

// Implementation of ReadSecret - verifies the secret is intact in VTL1
std::wstring VbsEnclave::Trusted::Implementation::ReadSecret()
{
    // Return the secret - this proves it's still intact in VTL1
    return std::wstring(g_secret_data);
}
