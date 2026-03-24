#include "pch.h"

#include "storage_post_setup.h"
#include "utils.h"

#include <veil/enclave/crypto.vtl1.h>

namespace storagepoc::trusted::post_setup
{
namespace
{
constexpr std::array<uint8_t, 4> kMetadataMagic = {'M', 'E', 'T', 'A'};
constexpr uint8_t kMetadataVersion = 1;
constexpr uint8_t kCipherAesGcmPocV1 = 1;

std::vector<uint8_t> BuildPayloadMetadata()
{
    // Minimal metadata schema for PoC (no nonce for now):
    // [magic:4][version:1][cipher_id:1]
    std::vector<uint8_t> metadata;
    metadata.reserve(6);
    metadata.insert(metadata.end(), kMetadataMagic.begin(), kMetadataMagic.end());
    metadata.push_back(kMetadataVersion);
    metadata.push_back(kCipherAesGcmPocV1);
    return metadata;
}

void ValidatePayloadMetadata(_In_ std::span<const uint8_t> metadata)
{
    THROW_HR_IF(E_INVALIDARG, metadata.size() != 6);
    THROW_HR_IF(E_INVALIDARG,
        !std::equal(kMetadataMagic.begin(), kMetadataMagic.end(), metadata.begin()));

    const auto version = metadata[4];
    const auto cipherId = metadata[5];

    THROW_HR_IF(E_NOTIMPL, version != kMetadataVersion);
    THROW_HR_IF(E_NOTIMPL, cipherId != kCipherAesGcmPocV1);
}

wil::secure_vector<uint8_t> LoadSymmetricKeyBytes(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob)
{
    auto mrenclaveHash = storagepoc::trusted::utils::ComputeMrenclaveHashMaterial();
    auto keyBytes = storagepoc::trusted::utils::RecoverSymmetricKeyFromProtectedBlob(
        protectedKeyMaterialBlob,
        mrenclaveHash,
        maybeResealedKeyMaterialBlob);

    return keyBytes;
}
} // namespace

HRESULT EncryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& plaintextPayload,
    _In_ uint32_t /*activityLevel*/,
    _In_ const std::wstring& /*logFilePath*/,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& ciphertextPayload,
    _Out_ std::vector<uint8_t>& payloadTag,
    _Out_ std::vector<uint8_t>& payloadMetadataBlob)
{
    try
    {
        auto keyBytes = LoadSymmetricKeyBytes(protectedKeyMaterialBlob, maybeResealedKeyMaterialBlob);
        auto symmetricKey = veil::vtl1::crypto::create_symmetric_key(keyBytes);

        // TODO(storage-poc): Replace fixed nonce strategy with per-record nonce + AAD.
        auto [ciphertext, tag] = veil::vtl1::crypto::encrypt(
            symmetricKey.get(),
            plaintextPayload,
            veil::vtl1::crypto::zero_nonce);

        ciphertextPayload.assign(ciphertext.begin(), ciphertext.end());
        payloadTag.assign(tag.begin(), tag.end());

        payloadMetadataBlob = BuildPayloadMetadata();

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT DecryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& ciphertextPayload,
    _In_ const std::vector<uint8_t>& payloadTag,
    _In_ const std::vector<uint8_t>& payloadMetadataBlob,
    _In_ uint32_t /*activityLevel*/,
    _In_ const std::wstring& /*logFilePath*/,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& plaintextPayload)
{
    try
    {
        ValidatePayloadMetadata(payloadMetadataBlob);

        auto keyBytes = LoadSymmetricKeyBytes(protectedKeyMaterialBlob, maybeResealedKeyMaterialBlob);
        auto symmetricKey = veil::vtl1::crypto::create_symmetric_key(keyBytes);

        auto plaintext = veil::vtl1::crypto::decrypt(
            symmetricKey.get(),
            ciphertextPayload,
            veil::vtl1::crypto::zero_nonce,
            payloadTag);

        plaintextPayload.assign(plaintext.begin(), plaintext.end());
        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::trusted::post_setup
