#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include <wil/result.h>
#include <veil/host/logger.vtl0.h>

namespace storagepoc::host
{
struct StorageArtifactPaths
{
    std::filesystem::path protectedKeyBlobPath;
    std::filesystem::path encryptedDataPath;
};

HRESULT RunSetupFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ std::span<const uint8_t> initialPayload,
    _In_ veil::vtl0::logger::logger& log);

HRESULT RunPostSetupProcessFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ veil::vtl0::logger::logger& log);
}
