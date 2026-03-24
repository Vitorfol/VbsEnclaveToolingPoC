#include "StorageFlowHandler.h"

#include <cstring>
#include <fstream>
#include <filesystem>

#include <wil/result_macros.h>

#include <VbsEnclave/HostApp/Stubs/Trusted.h>

namespace storagepoc::host
{
namespace
{
struct EncryptedDataEnvelope
{
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> metadata;
};

constexpr uint32_t kEnvelopeVersion = 1;

void AppendUint32(_Inout_ std::vector<uint8_t>& target, _In_ uint32_t value)
{
    auto p = reinterpret_cast<const uint8_t*>(&value);
    target.insert(target.end(), p, p + sizeof(value));
}

uint32_t ReadUint32(_In_ const std::vector<uint8_t>& source, _Inout_ size_t& offset)
{
    THROW_HR_IF(E_INVALIDARG, offset + sizeof(uint32_t) > source.size());

    uint32_t value = 0;
    std::memcpy(&value, source.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

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

std::vector<uint8_t> SerializeEnvelope(_In_ const EncryptedDataEnvelope& envelope)
{
    std::vector<uint8_t> serialized;
    serialized.reserve(
        sizeof(uint32_t) * 4 +
        envelope.ciphertext.size() +
        envelope.tag.size() +
        envelope.metadata.size());

    AppendUint32(serialized, kEnvelopeVersion);
    AppendUint32(serialized, static_cast<uint32_t>(envelope.ciphertext.size()));
    AppendUint32(serialized, static_cast<uint32_t>(envelope.tag.size()));
    AppendUint32(serialized, static_cast<uint32_t>(envelope.metadata.size()));

    serialized.insert(serialized.end(), envelope.ciphertext.begin(), envelope.ciphertext.end());
    serialized.insert(serialized.end(), envelope.tag.begin(), envelope.tag.end());
    serialized.insert(serialized.end(), envelope.metadata.begin(), envelope.metadata.end());

    return serialized;
}

EncryptedDataEnvelope DeserializeEnvelope(_In_ const std::vector<uint8_t>& serialized)
{
    size_t offset = 0;
    auto version = ReadUint32(serialized, offset);
    THROW_HR_IF(E_NOTIMPL, version != kEnvelopeVersion);

    auto ciphertextSize = ReadUint32(serialized, offset);
    auto tagSize = ReadUint32(serialized, offset);
    auto metadataSize = ReadUint32(serialized, offset);

    size_t expectedSize = offset + ciphertextSize + tagSize + metadataSize;
    THROW_HR_IF(E_INVALIDARG, expectedSize != serialized.size());

    EncryptedDataEnvelope envelope;
    envelope.ciphertext.assign(serialized.begin() + offset, serialized.begin() + offset + ciphertextSize);
    offset += ciphertextSize;
    envelope.tag.assign(serialized.begin() + offset, serialized.begin() + offset + tagSize);
    offset += tagSize;
    envelope.metadata.assign(serialized.begin() + offset, serialized.begin() + offset + metadataSize);
    return envelope;
}
} // namespace

HRESULT RunSetupFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ std::span<const uint8_t> initialPayload,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        // Setup is allowed only once for the selected persistence path.
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS),
            std::filesystem::exists(paths.protectedKeyBlobPath) || std::filesystem::exists(paths.encryptedDataPath));

        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        std::vector<uint8_t> protectedKeyBlob;
        std::vector<uint8_t> setupMetadata;

        THROW_IF_FAILED(enclaveInterface.StoragePocSetup_ProvisionKeyMaterial(
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            protectedKeyBlob,
            setupMetadata));

        std::vector<uint8_t> maybeResealedKeyBlob;
        std::vector<uint8_t> ciphertextPayload;
        std::vector<uint8_t> payloadTag;
        std::vector<uint8_t> payloadMetadata;
        std::vector<uint8_t> plaintext(initialPayload.begin(), initialPayload.end());

        THROW_IF_FAILED(enclaveInterface.StoragePocPostSetup_EncryptPayload(
            protectedKeyBlob,
            plaintext,
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            maybeResealedKeyBlob,
            ciphertextPayload,
            payloadTag,
            payloadMetadata));

        if (!maybeResealedKeyBlob.empty())
        {
            protectedKeyBlob = std::move(maybeResealedKeyBlob);
        }

        EncryptedDataEnvelope envelope;
        envelope.ciphertext = std::move(ciphertextPayload);
        envelope.tag = std::move(payloadTag);
        envelope.metadata = std::move(payloadMetadata);

        auto serializedData = SerializeEnvelope(envelope);

        SaveBinaryData(paths.protectedKeyBlobPath, protectedKeyBlob);
        SaveBinaryData(paths.encryptedDataPath, serializedData);

        (void)setupMetadata;
        // TODO(storage-poc): Persist setup metadata when schema is finalized.

        log.AddTimestampedLog(
            L"[Host] Setup flow completed. blob.txt and data.txt persisted.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT RunPostSetupProcessFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        auto protectedKeyBlob = LoadBinaryData(paths.protectedKeyBlobPath);
        auto serializedData = LoadBinaryData(paths.encryptedDataPath);
        auto envelope = DeserializeEnvelope(serializedData);

        std::vector<uint8_t> maybeResealedKeyBlob;
        std::vector<uint8_t> updatedCiphertext;
        std::vector<uint8_t> updatedTag;
        std::vector<uint8_t> updatedMetadata;

        THROW_IF_FAILED(enclaveInterface.StoragePocPostSetup_ProcessAndReencryptPayload(
            protectedKeyBlob,
            envelope.ciphertext,
            envelope.tag,
            envelope.metadata,
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            maybeResealedKeyBlob,
            updatedCiphertext,
            updatedTag,
            updatedMetadata));

        SaveIfNotEmpty(paths.protectedKeyBlobPath, maybeResealedKeyBlob);

        EncryptedDataEnvelope updatedEnvelope;
        updatedEnvelope.ciphertext = std::move(updatedCiphertext);
        updatedEnvelope.tag = std::move(updatedTag);
        updatedEnvelope.metadata = std::move(updatedMetadata);
        auto updatedSerializedData = SerializeEnvelope(updatedEnvelope);
        SaveBinaryData(paths.encryptedDataPath, updatedSerializedData);

        log.AddTimestampedLog(
            L"[Host] Post-setup process flow completed. data.txt overwritten.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::host
