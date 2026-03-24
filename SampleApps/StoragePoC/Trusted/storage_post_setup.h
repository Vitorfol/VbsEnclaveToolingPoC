#pragma once

#include <vector>

namespace storagepoc::trusted::post_setup
{
HRESULT EncryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& plaintextPayload,
    _In_ uint32_t activityLevel,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& ciphertextPayload,
    _Out_ std::vector<uint8_t>& payloadTag,
    _Out_ std::vector<uint8_t>& payloadMetadataBlob);

HRESULT DecryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& ciphertextPayload,
    _In_ const std::vector<uint8_t>& payloadTag,
    _In_ const std::vector<uint8_t>& payloadMetadataBlob,
    _In_ uint32_t activityLevel,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& plaintextPayload);

HRESULT ProcessAndReencryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& ciphertextPayload,
    _In_ const std::vector<uint8_t>& payloadTag,
    _In_ const std::vector<uint8_t>& payloadMetadataBlob,
    _In_ uint32_t activityLevel,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& updatedCiphertextPayload,
    _Out_ std::vector<uint8_t>& updatedPayloadTag,
    _Out_ std::vector<uint8_t>& updatedPayloadMetadataBlob);
}
