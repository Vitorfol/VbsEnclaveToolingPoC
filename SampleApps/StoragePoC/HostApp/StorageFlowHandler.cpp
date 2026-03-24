#include "StorageFlowHandler.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>

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

constexpr std::string_view kBlobFormat = "SPOC_BLOB_V1";
constexpr std::string_view kDataFormat = "SPOC_DATA_V1";

std::string BytesToHex(_In_ std::span<const uint8_t> bytes)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string output;
    output.resize(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        output[2 * i] = kHex[(bytes[i] >> 4) & 0x0F];
        output[2 * i + 1] = kHex[bytes[i] & 0x0F];
    }
    return output;
}

uint8_t HexNibble(_In_ char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return static_cast<uint8_t>(10 + ch - 'A');
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return static_cast<uint8_t>(10 + ch - 'a');
    }
    THROW_HR(E_INVALIDARG);
}

std::vector<uint8_t> HexToBytes(_In_ const std::string& hex)
{
    THROW_HR_IF(E_INVALIDARG, (hex.size() % 2) != 0);
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        auto high = HexNibble(hex[i]);
        auto low = HexNibble(hex[i + 1]);
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

std::unordered_map<std::string, std::string> ReadKeyValueFile(_In_ const std::filesystem::path& filePath)
{
    std::ifstream input(filePath, std::ios::in);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), !input.good());

    std::unordered_map<std::string, std::string> kv;
    std::string line;
    while (std::getline(input, line))
    {
        if (line.empty())
        {
            continue;
        }

        auto pos = line.find('=');
        THROW_HR_IF(E_INVALIDARG, pos == std::string::npos);

        auto key = line.substr(0, pos);
        auto value = line.substr(pos + 1);
        kv[std::move(key)] = std::move(value);
    }

    return kv;
}

void WriteBlobFile(
    _In_ const std::filesystem::path& filePath,
    _In_ std::span<const uint8_t> protectedKeyBlob)
{
    std::filesystem::create_directories(filePath.parent_path());
    std::ofstream output(filePath, std::ios::out | std::ios::trunc);
    THROW_HR_IF(E_FAIL, !output.good());

    output << "format=" << kBlobFormat << "\n";
    output << "wrapped_s_hex=" << BytesToHex(protectedKeyBlob) << "\n";
}

std::vector<uint8_t> ReadBlobFile(_In_ const std::filesystem::path& filePath)
{
    auto kv = ReadKeyValueFile(filePath);
    THROW_HR_IF(E_INVALIDARG, kv["format"] != kBlobFormat);
    return HexToBytes(kv["wrapped_s_hex"]);
}

void WriteDataFile(
    _In_ const std::filesystem::path& filePath,
    _In_ const EncryptedDataEnvelope& envelope)
{
    std::filesystem::create_directories(filePath.parent_path());
    std::ofstream output(filePath, std::ios::out | std::ios::trunc);
    THROW_HR_IF(E_FAIL, !output.good());

    output << "format=" << kDataFormat << "\n";
    output << "ciphertext_hex=" << BytesToHex(envelope.ciphertext) << "\n";
    output << "tag_hex=" << BytesToHex(envelope.tag) << "\n";
    output << "metadata_hex=" << BytesToHex(envelope.metadata) << "\n";
}

EncryptedDataEnvelope ReadDataFile(_In_ const std::filesystem::path& filePath)
{
    auto kv = ReadKeyValueFile(filePath);
    THROW_HR_IF(E_INVALIDARG, kv["format"] != kDataFormat);

    EncryptedDataEnvelope envelope;
    envelope.ciphertext = HexToBytes(kv["ciphertext_hex"]);
    envelope.tag = HexToBytes(kv["tag_hex"]);
    envelope.metadata = HexToBytes(kv["metadata_hex"]);
    return envelope;
}

void SaveBlobIfNotEmpty(_In_ const std::filesystem::path& filePath, _In_ std::span<const uint8_t> blob)
{
    if (!blob.empty())
    {
        WriteBlobFile(filePath, blob);
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
        // Setup is allowed only once for the selected persistence path.
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS),
            std::filesystem::exists(paths.protectedKeyBlobPath) || std::filesystem::exists(paths.encryptedDataPath));

        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        std::vector<uint8_t> protectedKeyBlob;

        THROW_IF_FAILED(enclaveInterface.StoragePocSetup_ProvisionKeyMaterial(
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            protectedKeyBlob));

        std::vector<uint8_t> maybeResealedKeyBlob;
        std::vector<uint8_t> ciphertextPayload;
        std::vector<uint8_t> payloadTag;
        std::vector<uint8_t> payloadMetadata;
        std::vector<uint8_t> plaintext {'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd'};

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

        WriteBlobFile(paths.protectedKeyBlobPath, protectedKeyBlob);
        WriteDataFile(paths.encryptedDataPath, envelope);

        log.AddTimestampedLog(
            L"[Host] Setup flow completed. blob.txt and data.txt persisted.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT RunPostSetupReadFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _Out_ std::vector<uint8_t>& plaintextPayload,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        auto protectedKeyBlob = ReadBlobFile(paths.protectedKeyBlobPath);
        auto envelope = ReadDataFile(paths.encryptedDataPath);

        std::vector<uint8_t> maybeResealedKeyBlob;

        THROW_IF_FAILED(enclaveInterface.StoragePocPostSetup_DecryptPayload(
            protectedKeyBlob,
            envelope.ciphertext,
            envelope.tag,
            envelope.metadata,
            static_cast<uint32_t>(log.GetLogLevel()),
            log.GetLogFilePath(),
            maybeResealedKeyBlob,
            plaintextPayload));

        SaveBlobIfNotEmpty(paths.protectedKeyBlobPath, maybeResealedKeyBlob);

        log.AddTimestampedLog(
            L"[Host] Post-setup read flow completed.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT RunPostSetupWriteFlow(
    _In_ void* enclave,
    _In_ const StorageArtifactPaths& paths,
    _In_ std::span<const uint8_t> plaintextPayload,
    _In_ veil::vtl0::logger::logger& log)
{
    try
    {
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        auto protectedKeyBlob = ReadBlobFile(paths.protectedKeyBlobPath);

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

        SaveBlobIfNotEmpty(paths.protectedKeyBlobPath, maybeResealedKeyBlob);

        EncryptedDataEnvelope envelope;
        envelope.ciphertext = std::move(ciphertextPayload);
        envelope.tag = std::move(payloadTag);
        envelope.metadata = std::move(payloadMetadata);
        WriteDataFile(paths.encryptedDataPath, envelope);

        log.AddTimestampedLog(
            L"[Host] Post-setup write flow completed. data.txt updated.",
            veil::any::logger::eventLevel::EVENT_LEVEL_INFO);

        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::host
