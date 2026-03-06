// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <array>

#define POC_ENCLAVE_FAMILY_ID \
    { \
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, \
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, \
    }

#define POC_ENCLAVE_IMAGE_ID \
    { \
        0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, \
        0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, \
    }

// Version: 1.0.0.0 -> 0x01000000
#define POC_ENCLAVE_IMAGE_VERSION 0x01000000 

#define POC_ENCLAVE_SVN 1

// The expected virtual size of the private address range for the enclave, 512MB
#define POC_ENCLAVE_ADDRESS_SPACE_SIZE 0x20000000 

// Enclave image creation policies
#ifndef ENCLAVE_MAX_THREADS
#define POC_ENCLAVE_MAX_THREADS 4
#endif

constexpr int EnclavePolicy_EnableDebuggingForDebugBuildsOnly
{
#ifdef _DEBUG
        IMAGE_ENCLAVE_POLICY_DEBUGGABLE
#endif
};

// VBS enclave configuration - included statically
extern "C" const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG),
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    EnclavePolicy_EnableDebuggingForDebugBuildsOnly,
    0,
    0,
    0,
    POC_ENCLAVE_FAMILY_ID,
    POC_ENCLAVE_IMAGE_ID,
    POC_ENCLAVE_IMAGE_VERSION,
    POC_ENCLAVE_SVN,
    POC_ENCLAVE_ADDRESS_SPACE_SIZE,
    POC_ENCLAVE_MAX_THREADS,
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE };

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    default:
        break;
    }
    return TRUE;
}
