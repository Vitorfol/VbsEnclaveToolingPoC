#include "StorageFlowHandler.h"

#include <fstream>

#include <wil/result_macros.h>

#include <VbsEnclave/HostApp/Stubs/Trusted.h>

namespace storagepoc::host
{
namespace
{
std::vector<uint8_t> LoadBinaryData(_In_ const std::filesystem::path& filePath)
{
    std::ifstream input(filePath, std::ios::binary);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), !input.good());

    input.seekg(0, std::ios::end);
    auto size = input.tellg();
    input.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!data.empty())
    {
        input.read(reinterpret_cast<char*>(data.data()), data.size());
    }

    return data;
}

void SaveBinaryData(_In_ const std::filesystem::path& filePath, _In_ std::span<const uint8_t> data)
{
    std::ofstream output(filePath, std::ios::binary | std::ios::trunc);
    THROW_HR_IF(E_FAIL, !output.good());

    if (!data.empty())
    {
        output.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
}

void SaveIfNotEmpty(_In_ const std::filesystem::path& filePath, _In_ std::span<const uint8_t> data)
{
    if (!data.empty())
    {
        SaveBinaryData(filePath, data);
    }
}
} // namespace

HRESULT RunSetupFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        std::vector<uint8_t> protectedKeyBlob;
        std::vector<uint8_t> setupMetadata;

        THROW_IF_FAILED(enclaveInterface.StoragePocSetup_ProvisionKeyMaterial(
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            protectedKeyBlob,
            setupMetadata));

        SaveBinaryData(paths.protectedKeyBlobPath, protectedKeyBlob);
        SaveBinaryData(paths.setupMetadataPath, setupMetadata);

        log.AddTimestampedLog(
            L"[Host] Setup flow completed. Protected key blob persisted.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT RunPostSetupEncryptFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ std::span<const uint8_t> plaintextPayload,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        auto protectedKeyBlob = LoadBinaryData(paths.protectedKeyBlobPath);

        std::vector<uint8_t> maybeResealedKeyBlob;
        std::vector<uint8_t> ciphertextPayload;
        std::vector<uint8_t> payloadTag;
        std::vector<uint8_t> payloadMetadata;

        std::vector<uint8_t> plaintext(plaintextPayload.begin(), plaintextPayload.end());

        THROW_IF_FAILED(enclaveInterface.StoragePocPostSetup_EncryptPayload(
            protectedKeyBlob,
            plaintext,
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            maybeResealedKeyBlob,
            ciphertextPayload,
            payloadTag,
            payloadMetadata));

        SaveIfNotEmpty(paths.protectedKeyBlobPath, maybeResealedKeyBlob);
        SaveBinaryData(paths.payloadCiphertextPath, ciphertextPayload);
        SaveBinaryData(paths.payloadTagPath, payloadTag);
        SaveBinaryData(paths.payloadMetadataPath, payloadMetadata);

        log.AddTimestampedLog(
            L"[Host] Post-setup encrypt flow completed. Ciphertext persisted.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT RunPostSetupDecryptFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _Out_ std::vector<uint8_t>& plaintextPayload,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        auto protectedKeyBlob = LoadBinaryData(paths.protectedKeyBlobPath);
        auto ciphertextPayload = LoadBinaryData(paths.payloadCiphertextPath);
        auto payloadTag = LoadBinaryData(paths.payloadTagPath);
        auto payloadMetadata = LoadBinaryData(paths.payloadMetadataPath);

        std::vector<uint8_t> maybeResealedKeyBlob;

        THROW_IF_FAILED(enclaveInterface.StoragePocPostSetup_DecryptPayload(
            protectedKeyBlob,
            ciphertextPayload,
            payloadTag,
            payloadMetadata,
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            maybeResealedKeyBlob,
            plaintextPayload));

        SaveIfNotEmpty(paths.protectedKeyBlobPath, maybeResealedKeyBlob);

        log.AddTimestampedLog(
            L"[Host] Post-setup decrypt flow completed.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::host
